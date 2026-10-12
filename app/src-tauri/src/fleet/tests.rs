//! Protokol správce a firemního Macu přes nedůvěryhodnou schránku: celá cesta
//! se schránkou v paměti (stejná pravidla jako SQL ve `relay/migrations`)
//! a živý test proti skutečné schránce (jen s aktivačním kódem v proměnné
//! `ANTISHIELD_FLEET_ACTIVATION`, spouští ho CI).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;

use antishield_core::cleanup::CleanCategory;
use antishield_core::fleet::{
    ACTIVATION_PREFIX, COMMAND, Command, CommandKind, FleetError, Identity, LastScan, MemoryState,
    OneTimeCode, ResultState, VERSION, sign_and_seal,
};
use antishield_core::status::ProtectionLevel;

use super::admin::AdminState;
use super::member::{Invitation, MemberState, Outcome, Received, ReportInput};
use super::relay::{CommandRow, InviteRow, RelayCommand, RelayDevice, RelayState};
use super::view::RelayStatus;

const NOW: u64 = 1_800_000_000_000;
const MINUTE: u64 = 60_000;

// ---------- Schránka v paměti ----------

struct Device {
    id: String,
    fleet: String,
    token: String,
    invite: String,
    bundle: String,
    report: Option<String>,
    last_seen: Option<u64>,
    left_notice: Option<String>,
    created: u64,
}

struct Cmd {
    id: String,
    fleet: String,
    device: String,
    envelope: String,
    expires: u64,
    delivered: Option<u64>,
    result: Option<String>,
}

#[derive(Default)]
struct MemoryRelay {
    now: u64,
    activations: HashMap<String, u32>,
    fleets: HashMap<String, String>,
    invites: HashMap<String, (String, String, u64, bool)>,
    devices: Vec<Device>,
    commands: Vec<Cmd>,
}

impl MemoryRelay {
    fn admin(&self, fleet: &str, token: &str) -> Result<(), String> {
        (self.fleets.get(fleet).map(String::as_str) == Some(token))
            .then_some(())
            .ok_or_else(|| "fleet_not_authorized".into())
    }

    fn device(&mut self, device: &str, token: &str) -> Result<&mut Device, String> {
        let now = self.now;
        let found = self
            .devices
            .iter_mut()
            .find(|d| d.id == device && d.token == token && d.left_notice.is_none())
            .ok_or_else(|| "fleet_not_authorized".to_string())?;
        found.last_seen = Some(now);
        Ok(found)
    }

    fn create(&mut self, activation: &str, fleet: &str, token: &str) -> Result<(), String> {
        let uses = self
            .activations
            .get_mut(activation)
            .filter(|uses| **uses > 0)
            .ok_or("fleet_activation_invalid")?;
        *uses -= 1;
        self.fleets.insert(fleet.into(), token.into());
        Ok(())
    }

    fn admin_invite(
        &mut self,
        fleet: &str,
        token: &str,
        id: &str,
        bundle: &str,
        expires: u64,
    ) -> Result<(), String> {
        self.admin(fleet, token)?;
        self.invites
            .insert(id.into(), (fleet.into(), bundle.into(), expires, false));
        Ok(())
    }

    fn invite(&self, id: &str) -> Option<InviteRow> {
        self.invites
            .get(id)
            .filter(|(_, _, expires, used)| !used && *expires > self.now)
            .map(|(_, bundle, _, _)| InviteRow {
                bundle: bundle.clone(),
            })
    }

    fn enroll(&mut self, id: &str, device: &str, token: &str, bundle: &str) -> Result<(), String> {
        let now = self.now;
        let invite = self
            .invites
            .get_mut(id)
            .filter(|(_, _, expires, used)| !used && *expires > now)
            .ok_or("fleet_invite_invalid")?;
        invite.3 = true;
        let fleet = invite.0.clone();
        self.devices.push(Device {
            id: device.into(),
            fleet,
            token: token.into(),
            invite: id.into(),
            bundle: bundle.into(),
            report: None,
            last_seen: Some(now),
            left_notice: None,
            created: now,
        });
        Ok(())
    }

    fn admin_state(&self, fleet: &str, token: &str) -> Result<RelayState, String> {
        self.admin(fleet, token)?;
        Ok(RelayState {
            now_ms: self.now,
            devices: self
                .devices
                .iter()
                .filter(|d| d.fleet == fleet)
                .map(|d| RelayDevice {
                    id: d.id.clone(),
                    bundle: d.bundle.clone(),
                    invite_token_id: d.invite.clone(),
                    report: d.report.clone(),
                    last_seen_ms: d.last_seen,
                    left_notice: d.left_notice.clone(),
                    created_at_ms: d.created,
                })
                .collect(),
            commands: self
                .commands
                .iter()
                .filter(|c| c.fleet == fleet)
                .map(|c| RelayCommand {
                    id: c.id.clone(),
                    delivered_at_ms: c.delivered,
                    result: c.result.clone(),
                })
                .collect(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn admin_command(
        &mut self,
        fleet: &str,
        token: &str,
        id: &str,
        device: &str,
        envelope: &str,
        expires: u64,
    ) -> Result<(), String> {
        self.admin(fleet, token)?;
        if !self
            .devices
            .iter()
            .any(|d| d.id == device && d.fleet == fleet && d.left_notice.is_none())
        {
            return Err("fleet_unknown_device".into());
        }
        self.commands.push(Cmd {
            id: id.into(),
            fleet: fleet.into(),
            device: device.into(),
            envelope: envelope.into(),
            expires,
            delivered: None,
            result: None,
        });
        Ok(())
    }

    fn poll(&mut self, device: &str, token: &str) -> Result<Vec<CommandRow>, String> {
        self.device(device, token)?;
        let now = self.now;
        Ok(self
            .commands
            .iter_mut()
            .filter(|c| {
                c.device == device
                    && c.result.is_none()
                    && c.expires > now
                    && c.delivered.is_none_or(|at| at + 10 * MINUTE < now)
            })
            .map(|c| {
                c.delivered = Some(now);
                CommandRow {
                    id: c.id.clone(),
                    envelope: c.envelope.clone(),
                }
            })
            .collect())
    }

    fn report(&mut self, device: &str, token: &str, report: &str) -> Result<(), String> {
        self.device(device, token)?.report = Some(report.into());
        Ok(())
    }

    fn result(
        &mut self,
        device: &str,
        token: &str,
        command: &str,
        result: &str,
    ) -> Result<(), String> {
        self.device(device, token)?;
        let cmd = self
            .commands
            .iter_mut()
            .find(|c| c.id == command && c.device == device)
            .ok_or("fleet_unknown_command")?;
        cmd.result = Some(result.into());
        Ok(())
    }

    fn leave(&mut self, device: &str, token: &str, notice: &str) -> Result<(), String> {
        self.device(device, token)?.left_notice = Some(notice.into());
        Ok(())
    }

    fn remove_device(&mut self, fleet: &str, token: &str, device: &str) -> Result<(), String> {
        self.admin(fleet, token)?;
        self.devices.retain(|d| d.id != device);
        self.commands.retain(|c| c.device != device);
        Ok(())
    }
}

// ---------- Pomocníci ----------

fn report_input(model: &str) -> ReportInput {
    ReportInput {
        app_version: "0.7.0".into(),
        os_version: "macOS 26.0.1".into(),
        model: model.into(),
        protection: ProtectionLevel::Monitored,
        protection_note: None,
        rules_version: "2026.10.12".into(),
        rules_checked_at_ms: Some(NOW),
        last_scan: Some(LastScan {
            at_ms: NOW,
            files: 10,
            threats: 0,
        }),
        threats: vec![],
        quarantined: 0,
        disk: None,
        memory: MemoryState {
            total: 16,
            used: 8,
            pressure: None,
        },
        uptime_secs: 60,
        cleanup: None,
    }
}

struct World {
    relay: MemoryRelay,
    admin: AdminState,
}

impl World {
    fn new() -> Self {
        let mut relay = MemoryRelay {
            now: NOW,
            ..MemoryRelay::default()
        };
        let activation = OneTimeCode::generate(ACTIVATION_PREFIX).unwrap();
        relay.activations.insert(activation.canonical(), 1);
        let admin = AdminState::new("H&H Security", "Martin Horák", NOW).unwrap();
        relay
            .create(&activation.canonical(), &admin.fleet_id, &admin.admin_token)
            .unwrap();
        // Aktivační kód jde použít jen jednou.
        assert_eq!(
            relay.create(&activation.canonical(), "other", "x"),
            Err("fleet_activation_invalid".into())
        );
        Self { relay, admin }
    }

    /// Pozvánka, připojení Macu a ověření u správce.
    fn enroll(&mut self, name: &str) -> MemberState {
        let (invite, bundle) = self.admin.invite(name, self.relay.now).unwrap();
        self.relay
            .admin_invite(
                &self.admin.fleet_id,
                &self.admin.admin_token,
                &invite.token_id,
                &bundle,
                invite.expires_at_ms,
            )
            .unwrap();
        self.admin.invites.push(invite.clone());

        let code = Invitation::parse_code(&invite.code.to_lowercase().replace('-', " ")).unwrap();
        let invitation =
            Invitation::open(&code, self.relay.invite(&code.token_id()), self.relay.now).unwrap();
        assert_eq!(invitation.bundle.device_name, name);
        assert_eq!(
            invitation.bundle.admin.fingerprint(),
            self.admin.fingerprint()
        );
        let (member, device_bundle) = MemberState::join(&invitation, self.relay.now).unwrap();
        self.relay
            .enroll(
                &code.token_id(),
                &member.device_id,
                &member.device_token,
                &device_bundle,
            )
            .unwrap();
        // Pozvánka je jednorázová.
        assert!(self.relay.invite(&code.token_id()).is_none());
        self.sync();
        member
    }

    fn sync(&mut self) -> Vec<String> {
        let state = self
            .relay
            .admin_state(&self.admin.fleet_id, &self.admin.admin_token)
            .unwrap();
        self.admin.ingest(&state, self.relay.now).remove
    }

    fn send(&mut self, device: &str, kind: CommandKind, categories: &[CleanCategory]) -> String {
        let (command, sealed) = self
            .admin
            .command(device, kind, categories, self.relay.now)
            .unwrap();
        self.relay
            .admin_command(
                &self.admin.fleet_id,
                &self.admin.admin_token,
                &command.id,
                device,
                &sealed,
                command.expires_at_ms,
            )
            .unwrap();
        let id = command.id.clone();
        self.admin.record_command(command);
        id
    }

    fn post(
        &mut self,
        member: &mut MemberState,
        id: &str,
        state: ResultState,
        outcome: Outcome,
    ) -> String {
        let sealed = member
            .result(id, state, outcome, None, self.relay.now)
            .unwrap();
        self.relay
            .result(&member.device_id, &member.device_token, id, &sealed)
            .unwrap();
        sealed
    }

    fn view_state(&self, device: &str, command: &str) -> &'static str {
        self.admin
            .view(&RelayStatus::default(), self.relay.now)
            .devices
            .into_iter()
            .find(|d| d.id == device)
            .and_then(|d| d.commands.into_iter().find(|c| c.id == command))
            .map_or("missing", |c| c.state)
    }
}

// ---------- Testy ----------

#[test]
fn admin_and_mac_talk_only_through_signed_sealed_messages() {
    let mut world = World::new();
    let mut petr = world.enroll("Petr Novák");
    let device = petr.device_id.clone();
    {
        let view = world.admin.view(&RelayStatus::default(), NOW);
        assert_eq!(view.devices.len(), 1);
        assert_eq!(view.devices[0].name, "Petr Novák");
        assert_eq!(
            view.devices[0].fingerprint,
            petr.identity().public().fingerprint()
        );
        assert!(view.invites.is_empty(), "the used invite is gone");
    }

    // Zpráva o stavu dorazí ověřená.
    let report = petr
        .report(report_input("MacBook Pro (Apple M3 Pro)"), NOW)
        .unwrap();
    world
        .relay
        .report(&device, &petr.device_token, &report)
        .unwrap();
    world.sync();
    let model = |w: &World| {
        w.admin.devices[0]
            .report
            .as_ref()
            .map(|r| r.model.clone())
            .unwrap_or_default()
    };
    assert_eq!(model(&world), "MacBook Pro (Apple M3 Pro)");

    // Úklid: část hned, část se souhlasem.
    let id = world.send(
        &device,
        CommandKind::Cleanup,
        &[CleanCategory::AppCaches, CleanCategory::Installers],
    );
    assert_eq!(world.view_state(&device, &id), "queued");
    let rows = world.relay.poll(&device, &petr.device_token).unwrap();
    assert_eq!(rows.len(), 1);
    world.sync();
    assert_eq!(world.view_state(&device, &id), "delivered");
    let Received::New(command) = petr.receive(&rows[0].id, &rows[0].envelope, NOW) else {
        panic!("a valid command is accepted");
    };
    assert_eq!(
        petr.policy.split(&command.categories),
        (
            vec![CleanCategory::AppCaches],
            vec![CleanCategory::Installers]
        )
    );
    world.post(&mut petr, &id, ResultState::Running, Outcome::default());
    let waiting = Outcome {
        freed_bytes: 100,
        ..Outcome::default()
    };
    let sealed = world.post(&mut petr, &id, ResultState::AwaitingConsent, waiting);
    world.sync();
    assert_eq!(world.view_state(&device, &id), "awaitingConsent");

    // Opakované doručení stejného příkazu se neprovede, jen se znovu pošle výsledek.
    match petr.receive(&rows[0].id, &rows[0].envelope, NOW + 1) {
        Received::Repost(again) => assert_eq!(again, sealed),
        other => panic!("replay must not run again: {other:?}"),
    }
    let done = Outcome {
        freed_bytes: 100,
        trashed_bytes: 50,
        ..Outcome::default()
    };
    world.post(&mut petr, &id, ResultState::Done, done);
    world.sync();
    assert_eq!(world.view_state(&device, &id), "done");
    let view = world.admin.view(&RelayStatus::default(), NOW);
    let shown = &view.devices[0].commands[0];
    assert_eq!((shown.freed_bytes, shown.trashed_bytes), (100, 50));

    // Starší zprávu (schránka ji vrátí) správce nepřijme místo novější.
    let newer = petr
        .report(report_input("MacBook Pro (novější)"), NOW + 2)
        .unwrap();
    world
        .relay
        .report(&device, &petr.device_token, &newer)
        .unwrap();
    world.sync();
    assert_eq!(model(&world), "MacBook Pro (novější)");
    world
        .relay
        .report(&device, &petr.device_token, &report)
        .unwrap();
    world.sync();
    assert_eq!(
        model(&world),
        "MacBook Pro (novější)",
        "replayed old report ignored"
    );

    // Uživatel Mac odpojí: správce to pozná z podepsaného oznámení.
    let notice = petr.leave_notice(NOW).unwrap();
    world
        .relay
        .leave(&device, &petr.device_token, &notice)
        .unwrap();
    world.sync();
    assert!(world.admin.view(&RelayStatus::default(), NOW).devices[0].left);
    assert!(
        world
            .admin
            .command(&device, CommandKind::Scan, &[], NOW)
            .is_err()
    );
}

#[test]
fn the_relay_cannot_forge_commands_keys_or_results() {
    let mut world = World::new();
    let mut jana = world.enroll("Jana Dvořáková");
    let device = jana.device_id.clone();

    // Příkaz podepsaný kýmkoli jiným než správcem (schránka, útočník).
    let attacker = Identity::generate().unwrap();
    let forged = Command {
        v: VERSION,
        id: "2b4e28ba-2fa1-41d2-883f-0016d3cca427".into(),
        fleet_id: jana.fleet_id.clone(),
        device_id: device.clone(),
        kind: CommandKind::Cleanup,
        categories: vec![CleanCategory::AppCaches],
        issued_at_ms: NOW,
        expires_at_ms: NOW + MINUTE,
    };
    let sealed = sign_and_seal(&attacker, &jana.identity().public(), COMMAND, &forged).unwrap();
    assert!(matches!(
        jana.receive(&forged.id, &sealed, NOW),
        Received::Reject(FleetError::NotAuthentic)
    ));

    // Pravý příkaz pod cizím identifikátorem ve schránce.
    let id = world.send(&device, CommandKind::Scan, &[]);
    let rows = world.relay.poll(&device, &jana.device_token).unwrap();
    assert!(matches!(
        jana.receive(
            "2b4e28ba-2fa1-41d2-883f-0016d3cca427",
            &rows[0].envelope,
            NOW
        ),
        Received::Reject(FleetError::WrongTarget)
    ));
    // Výsledek podepsaný jiným klíčem (jiný Mac se vydává za tento) správce nepřijme.
    let mut impostor = world.enroll("Podvodník");
    impostor.device_id = device.clone();
    let fake = impostor
        .result(&id, ResultState::Done, Outcome::default(), None, NOW)
        .unwrap();
    world
        .relay
        .result(&device, &jana.device_token, &id, &fake)
        .unwrap();
    world.sync();
    assert_eq!(
        world.view_state(&device, &id),
        "delivered",
        "forged result ignored"
    );

    // Nový Mac s klíči, které schránka podstrčila místo pravých: správce ho nepřijme.
    let (invite, bundle) = world.admin.invite("Karel Procházka", NOW).unwrap();
    world
        .relay
        .admin_invite(
            &world.admin.fleet_id,
            &world.admin.admin_token,
            &invite.token_id,
            &bundle,
            invite.expires_at_ms,
        )
        .unwrap();
    world.admin.invites.push(invite.clone());
    let code = Invitation::parse_code(&invite.code).unwrap();
    let invitation = Invitation::open(&code, world.relay.invite(&code.token_id()), NOW).unwrap();
    let (karel, _) = MemberState::join(&invitation, NOW).unwrap();
    let wrong_code = OneTimeCode::generate("HHF1").unwrap();
    let swapped = wrong_code
        .bind(
            antishield_core::fleet::DEVICE_BUNDLE,
            &antishield_core::fleet::DeviceBundle {
                v: VERSION,
                fleet_id: world.admin.fleet_id.clone(),
                token_id: code.token_id(),
                device_id: karel.device_id.clone(),
                device: attacker.public(),
            },
        )
        .unwrap();
    world
        .relay
        .enroll(
            &code.token_id(),
            &karel.device_id,
            &karel.device_token,
            &swapped,
        )
        .unwrap();
    let removed = world.sync();
    assert_eq!(removed, vec![karel.device_id.clone()]);
    assert!(!world.admin.devices.iter().any(|d| d.id == karel.device_id));

    // Soubory uživatele a Koš správce ani neodešle.
    for category in [CleanCategory::LargeFiles, CleanCategory::Trash] {
        assert!(matches!(
            world
                .admin
                .command(&device, CommandKind::Cleanup, &[category], NOW),
            Err(FleetError::NotAllowed(_))
        ));
    }
}

#[test]
fn removing_a_mac_waits_for_its_signed_goodbye() {
    let mut world = World::new();
    let mut eva = world.enroll("Eva Kučerová");
    let device = eva.device_id.clone();
    let (command, sealed) = world
        .admin
        .command(&device, CommandKind::Unenroll, &[], NOW)
        .unwrap();
    world
        .relay
        .admin_command(
            &world.admin.fleet_id,
            &world.admin.admin_token,
            &command.id,
            &device,
            &sealed,
            command.expires_at_ms,
        )
        .unwrap();
    let id = command.id.clone();
    world.admin.record_command(command);
    // Odebíraný Mac už v přehledu není a další příkazy nedostane.
    assert!(
        world
            .admin
            .view(&RelayStatus::default(), NOW)
            .devices
            .is_empty()
    );
    assert!(
        world
            .admin
            .command(&device, CommandKind::Scan, &[], NOW)
            .is_err()
    );
    assert!(world.sync().is_empty(), "not yet confirmed by the Mac");

    let rows = world.relay.poll(&device, &eva.device_token).unwrap();
    let Received::New(cmd) = eva.receive(&rows[0].id, &rows[0].envelope, NOW) else {
        panic!("unenroll is a valid command");
    };
    assert_eq!(cmd.kind, CommandKind::Unenroll);
    world.post(&mut eva, &id, ResultState::Done, Outcome::default());
    let remove = world.sync();
    assert_eq!(remove, vec![device.clone()]);
    world
        .relay
        .remove_device(&world.admin.fleet_id, &world.admin.admin_token, &device)
        .unwrap();
    world.admin.forget_device(&device);
    assert!(world.admin.devices.is_empty());
    // Smazaný Mac se ve schránce už neohlásí.
    assert!(world.relay.poll(&device, &eva.device_token).is_err());
}

#[test]
fn consent_requests_expire_and_floods_are_refused() {
    let mut world = World::new();
    let mut lucie = world.enroll("Lucie Černá");
    lucie.add_approval(super::member::Approval {
        id: "a".into(),
        categories: vec![CleanCategory::Installers],
        bytes: 10,
        requested_at_ms: NOW,
        expires_at_ms: NOW + MINUTE,
        freed_bytes: 0,
        trashed_bytes: 0,
    });
    assert!(lucie.take_expired_approvals(NOW).is_empty());
    assert_eq!(lucie.take_expired_approvals(NOW + MINUTE).len(), 1);
    assert!(lucie.approvals.is_empty());

    // Víc než 30 příkazů za hodinu Mac odmítne.
    let device = lucie.device_id.clone();
    for _ in 0..super::member::MAX_COMMANDS_PER_HOUR {
        world.send(&device, CommandKind::Scan, &[]);
    }
    let extra = world.send(&device, CommandKind::Scan, &[]);
    let rows = world.relay.poll(&device, &lucie.device_token).unwrap();
    let mut refused = 0;
    for row in rows {
        match lucie.receive(&row.id, &row.envelope, NOW) {
            Received::New(_) => {}
            Received::Reject(FleetError::NotAllowed(_)) => {
                refused += 1;
                assert_eq!(row.id, extra);
            }
            other => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!(refused, 1);
}

/// Celá cesta proti skutečné schránce (Supabase). Firma vznikne s aktivačním
/// kódem z prostředí a na konci se smaže.
#[test]
#[ignore = "needs the live relay and ANTISHIELD_FLEET_ACTIVATION"]
fn live_relay_round_trip() {
    let activation = std::env::var("ANTISHIELD_FLEET_ACTIVATION").expect("activation code");
    tauri::async_runtime::block_on(async move {
        let relay = super::relay::Relay::new().unwrap();
        let now = crate::state::now_ms();
        let mut admin = AdminState::new("AntiShield CI", "CI", now).unwrap();
        let code = OneTimeCode::parse(ACTIVATION_PREFIX, &activation).unwrap();
        relay
            .create(&code.canonical(), &admin.fleet_id, &admin.admin_token)
            .await
            .unwrap();
        let (fleet, token) = (admin.fleet_id.clone(), admin.admin_token.clone());
        let outcome = async {
            let (invite, bundle) = admin.invite("CI Mac", now).unwrap();
            relay
                .admin_invite(
                    &fleet,
                    &token,
                    &invite.token_id,
                    &bundle,
                    invite.expires_at_ms,
                )
                .await
                .unwrap();
            admin.invites.push(invite.clone());
            let code = Invitation::parse_code(&invite.code).unwrap();
            let row = relay.invite(&code.token_id()).await.unwrap();
            let invitation = Invitation::open(&code, row, now).unwrap();
            let (mut member, device_bundle) = MemberState::join(&invitation, now).unwrap();
            relay
                .enroll(
                    &code.token_id(),
                    &member.device_id,
                    &member.device_token,
                    &device_bundle,
                )
                .await
                .unwrap();
            assert!(relay.invite(&code.token_id()).await.unwrap().is_none());

            let state = relay.admin_state(&fleet, &token).await.unwrap();
            assert!(
                admin
                    .ingest(&state, crate::state::now_ms())
                    .remove
                    .is_empty()
            );
            assert_eq!(admin.devices.len(), 1);

            let report = member
                .report(report_input("CI runner"), crate::state::now_ms())
                .unwrap();
            relay
                .report(&member.device_id, &member.device_token, &report)
                .await
                .unwrap();

            let (command, sealed) = admin
                .command(
                    &member.device_id,
                    CommandKind::Scan,
                    &[],
                    crate::state::now_ms(),
                )
                .unwrap();
            relay
                .admin_command(
                    &fleet,
                    &token,
                    &command.id,
                    &member.device_id,
                    &sealed,
                    command.expires_at_ms,
                )
                .await
                .unwrap();
            let id = command.id.clone();
            admin.record_command(command);

            let rows = relay
                .poll(&member.device_id, &member.device_token)
                .await
                .unwrap();
            assert_eq!(rows.len(), 1);
            let Received::New(_) =
                member.receive(&rows[0].id, &rows[0].envelope, crate::state::now_ms())
            else {
                panic!("the command arrives intact");
            };
            let done = Outcome {
                files: 42,
                ..Outcome::default()
            };
            let result = member
                .result(&id, ResultState::Done, done, None, crate::state::now_ms())
                .unwrap();
            relay
                .result(&member.device_id, &member.device_token, &id, &result)
                .await
                .unwrap();
            assert!(
                relay
                    .poll(&member.device_id, &member.device_token)
                    .await
                    .unwrap()
                    .is_empty()
            );

            let state = relay.admin_state(&fleet, &token).await.unwrap();
            admin.ingest(&state, crate::state::now_ms());
            let view = admin.view(&RelayStatus::default(), crate::state::now_ms());
            assert_eq!(view.devices[0].commands[0].state, "done");
            assert_eq!(view.devices[0].commands[0].files, 42);
            assert_eq!(
                view.devices[0].report.as_ref().map(|r| r.model.as_str()),
                Some("CI runner")
            );

            // Bez správného tokenu schránka nic nevydá.
            assert_eq!(
                relay
                    .poll(&member.device_id, "wrong-token")
                    .await
                    .unwrap_err(),
                super::relay::RelayError::Rejected("fleet_not_authorized".into())
            );
            assert!(relay.admin_state(&fleet, "wrong-token").await.is_err());

            let notice = member.leave_notice(crate::state::now_ms()).unwrap();
            relay
                .leave(&member.device_id, &member.device_token, &notice)
                .await
                .unwrap();
            let state = relay.admin_state(&fleet, &token).await.unwrap();
            admin.ingest(&state, crate::state::now_ms());
            assert!(
                admin
                    .view(&RelayStatus::default(), crate::state::now_ms())
                    .devices[0]
                    .left
            );
        };
        // Úklid i po neúspěchu: firma se ze schránky vždy smaže.
        let result = futures_catch(outcome).await;
        relay.admin_delete_fleet(&fleet, &token).await.unwrap();
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

/// Zachytí panic v testu, aby úklid ve schránce proběhl vždy.
async fn futures_catch<F: std::future::Future<Output = ()>>(
    future: F,
) -> Result<(), Box<dyn std::any::Any + Send>> {
    let mut future = std::pin::pin!(future);
    std::future::poll_fn(move |cx| {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| future.as_mut().poll(cx))) {
            Ok(std::task::Poll::Ready(())) => std::task::Poll::Ready(Ok(())),
            Ok(std::task::Poll::Pending) => std::task::Poll::Pending,
            Err(panic) => std::task::Poll::Ready(Err(panic)),
        }
    })
    .await
}

#[test]
fn relay_state_json_from_sql_is_understood() {
    // Stejný tvar, jaký skládá `antishield_fleet_admin_state` (jsonb_build_object).
    let json = r#"{
        "nowMs": 1800000000000,
        "devices": [{
            "id": "1b4e28ba-2fa1-41d2-883f-0016d3cca427",
            "bundle": "{\"p\":\"x\",\"m\":\"y\"}",
            "inviteTokenId": "abcdefghijklmnopqrstuv",
            "report": null,
            "reportAtMs": null,
            "lastSeenMs": 1799999990000,
            "leftNotice": null,
            "createdAtMs": 1799999000000
        }],
        "commands": [{
            "id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
            "deviceId": "1b4e28ba-2fa1-41d2-883f-0016d3cca427",
            "createdAtMs": 1799999995000,
            "expiresAtMs": 1800604800000,
            "deliveredAtMs": null,
            "result": null,
            "resultAtMs": null
        }],
        "invites": [{"tokenId": "abc", "expiresAtMs": 1, "usedAtMs": null, "deviceId": null}]
    }"#;
    let state: RelayState = serde_json::from_str(json).unwrap();
    assert_eq!(state.now_ms, NOW);
    assert_eq!(state.devices[0].last_seen_ms, Some(1_799_999_990_000));
    assert!(state.devices[0].report.is_none());
    assert_eq!(state.commands[0].delivered_at_ms, None);
    // Řádky z `antishield_fleet_poll` a `antishield_fleet_invite`.
    let rows: Vec<CommandRow> = serde_json::from_str(
        r#"[{"id": "7c9e6679-7425-40de-944b-e07fc1f90ae7", "envelope": "AQ"}]"#,
    )
    .unwrap();
    assert_eq!(rows[0].envelope, "AQ");
    let invites: Vec<InviteRow> =
        serde_json::from_str(r#"[{"bundle": "b", "expires_at_ms": 1800000000000}]"#).unwrap();
    assert_eq!(invites[0].bundle, "b");
}

/// Smlouva se skutečnou schránkou bez zakládání dat: každá funkce se zavolá
/// s neplatnými údaji a musí odpovědět svým kódem odmítnutí. Odhalí špatné
/// názvy parametrů (PostgREST by funkci nenašel) i špatné zpracování chyb.
#[test]
#[ignore = "needs the live relay"]
fn live_relay_contract() {
    use super::relay::RelayError::Rejected;
    tauri::async_runtime::block_on(async {
        let relay = super::relay::Relay::new().unwrap();
        let id = || antishield_core::fleet::random_id().unwrap();
        let token = antishield_core::fleet::random_token().unwrap();
        let soon = crate::state::now_ms() + 24 * 60 * MINUTE;
        let rejected = |code: &str| Rejected(code.to_string());
        let bogus = OneTimeCode::generate(ACTIVATION_PREFIX)
            .unwrap()
            .canonical();
        assert_eq!(
            relay.create(&bogus, &id(), &token).await.unwrap_err(),
            rejected("fleet_activation_invalid")
        );
        assert_eq!(
            relay
                .admin_invite(&id(), &token, "abcdefghijklmnopqrstuv", "b", soon)
                .await
                .unwrap_err(),
            rejected("fleet_not_authorized")
        );
        assert_eq!(
            relay.admin_state(&id(), &token).await.unwrap_err(),
            rejected("fleet_not_authorized")
        );
        assert_eq!(
            relay
                .admin_command(&id(), &token, &id(), &id(), "e", soon)
                .await
                .unwrap_err(),
            rejected("fleet_not_authorized")
        );
        assert_eq!(
            relay
                .admin_remove_device(&id(), &token, &id())
                .await
                .unwrap_err(),
            rejected("fleet_not_authorized")
        );
        assert_eq!(
            relay.admin_delete_fleet(&id(), &token).await.unwrap_err(),
            rejected("fleet_not_authorized")
        );
        assert!(
            relay
                .invite("abcdefghijklmnopqrstuv")
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            relay
                .enroll("abcdefghijklmnopqrstuv", &id(), &token, "b")
                .await
                .unwrap_err(),
            rejected("fleet_invite_invalid")
        );
        assert_eq!(
            relay.poll(&id(), &token).await.unwrap_err(),
            rejected("fleet_not_authorized")
        );
        assert_eq!(
            relay.report(&id(), &token, "r").await.unwrap_err(),
            rejected("fleet_not_authorized")
        );
        assert_eq!(
            relay.result(&id(), &token, &id(), "r").await.unwrap_err(),
            rejected("fleet_not_authorized")
        );
        assert_eq!(
            relay.leave(&id(), &token, "n").await.unwrap_err(),
            rejected("fleet_not_authorized")
        );
    });
}

#[test]
fn commands_cut_off_by_a_restart_are_reported_as_failed() {
    let mut world = World::new();
    let mut ondrej = world.enroll("Ondřej Veselý");
    let device = ondrej.device_id.clone();
    let scan = world.send(&device, CommandKind::Scan, &[]);
    let cleanup = world.send(&device, CommandKind::Cleanup, &[CleanCategory::Installers]);
    let rows = world.relay.poll(&device, &ondrej.device_token).unwrap();
    for row in &rows {
        assert!(matches!(
            ondrej.receive(&row.id, &row.envelope, NOW),
            Received::New(_)
        ));
    }
    world.post(&mut ondrej, &scan, ResultState::Running, Outcome::default());
    world.post(
        &mut ondrej,
        &cleanup,
        ResultState::AwaitingConsent,
        Outcome::default(),
    );
    ondrej.add_approval(super::member::Approval {
        id: cleanup.clone(),
        categories: vec![CleanCategory::Installers],
        bytes: 1,
        requested_at_ms: NOW,
        expires_at_ms: NOW + MINUTE,
        freed_bytes: 0,
        trashed_bytes: 0,
    });
    // Kontrola běžela, když aplikace skončila; úklid čeká na souhlas.
    assert_eq!(ondrej.interrupted(), vec![scan.clone()]);
    world.post(&mut ondrej, &scan, ResultState::Failed, Outcome::default());
    assert!(ondrej.interrupted().is_empty());
}
