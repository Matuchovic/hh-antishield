//! `antishield` – vývojářský nástroj nad jádrem H&H AntiShield.
//!
//! Návratové kódy (jako u běžných skenerů): 0 = bez nálezu, 1 = nález,
//! 2 = chyba, zrušení nebo neúplná kontrola.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::mpsc::{self, Sender};

use antishield_core::audit::verify_dir;
use antishield_core::error::ErrorDto;
use antishield_core::rules::{RulePack, builtin_trusted_keys};
use antishield_core::{
    Engine, EngineConfig, EngineError, RuleSource, ScanEvent, ScanObserver, ScanOutcome,
    ScanRequest, ScanSummary,
};
use clap::{Parser, Subcommand};

mod forge;

#[derive(Parser)]
#[command(
    name = "antishield",
    version,
    about = "H&H AntiShield – vývojářský nástroj"
)]
struct Cli {
    /// Adresář pro data enginu (auditní log).
    #[arg(long, global = true, default_value = "antishield-data")]
    data_dir: PathBuf,
    /// Vlastní sada pravidel místo zabudované testovací sady.
    #[arg(long, global = true, requires = "rules_sig")]
    rules_pack: Option<PathBuf>,
    /// Podpis k vlastní sadě pravidel.
    #[arg(long, global = true, requires = "rules_pack")]
    rules_sig: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Zkontroluje soubory a složky (jen čte, nic nemění).
    Scan {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Výstup jako JSON (souhrn kontroly).
        #[arg(long)]
        json: bool,
        /// Maximální velikost souboru v bajtech.
        #[arg(long)]
        max_size: Option<u64>,
        /// Procházet i jiné svazky pod kořenem.
        #[arg(long)]
        cross_volumes: bool,
    },
    /// Ověří detekci na vzorku v paměti.
    Selftest {
        #[arg(long)]
        json: bool,
    },
    /// Vypíše verzi enginu, pravidel a stav komponent.
    Info,
    /// Práce se sadami pravidel.
    Rules {
        #[command(subcommand)]
        command: RulesCommand,
    },
    /// Auditní log.
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
    /// Firemní správa (pro provozovatele schránky).
    Fleet {
        #[command(subcommand)]
        command: FleetCommand,
    },
}

#[derive(Subcommand)]
enum FleetCommand {
    /// Vytvoří jednorázový aktivační kód pro založení firmy a příkaz SQL pro schránku.
    Activation {
        /// Platnost kódu ve dnech.
        #[arg(long, default_value_t = 14)]
        days: u32,
        /// Poznámka do schránky (komu kód patří).
        #[arg(long, default_value = "")]
        note: String,
        /// Kolikrát jde kód použít (1 pro správce, víc pro živý test v CI).
        #[arg(long, default_value_t = 1)]
        uses: u32,
    },
}

#[derive(Subcommand)]
enum RulesCommand {
    /// Ověří podpis a obsah sady pravidel zabudovanými klíči.
    Verify { pack: PathBuf, signature: PathBuf },
    /// Sestaví produkční sadu z balíčku YARA Forge (jen licence vhodné ke komerčnímu použití).
    Build {
        /// Základní sada (klasická pravidla, EICAR).
        #[arg(long)]
        base: PathBuf,
        /// Neškodné pravidlo pro self-test YARA.
        #[arg(long)]
        selftest: PathBuf,
        /// Balíček YARA Forge (yara-rules-core.yar).
        #[arg(long)]
        forge: PathBuf,
        #[arg(long)]
        sequence: u64,
        #[arg(long)]
        version: String,
        /// Platnost sady ve dnech.
        #[arg(long, default_value_t = 45)]
        valid_days: i64,
        /// Selhat, když sada obsahuje méně pravidel YARA.
        #[arg(long, default_value_t = 1)]
        min_yara_rules: usize,
        #[arg(long)]
        out: PathBuf,
    },
    /// Vygeneruje nový pár klíčů Ed25519 (soukromý klíč nikdy necommitovat).
    #[cfg(feature = "signing")]
    Keygen {
        #[arg(long)]
        key_id: String,
        #[arg(long)]
        out_dir: PathBuf,
    },
    /// Podepíše sadu pravidel.
    #[cfg(feature = "signing")]
    Sign {
        #[arg(long)]
        pack: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        key_id: String,
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Subcommand)]
enum AuditCommand {
    /// Ověří hashový řetězec auditního logu.
    Verify,
}

struct ChannelObserver(Sender<ScanEvent>);

impl ScanObserver for ChannelObserver {
    fn on_event(&self, event: ScanEvent) {
        let _ = self.0.send(event);
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("chyba: {err}");
            ExitCode::from(2)
        }
    }
}

fn engine_config(cli: &Cli) -> EngineConfig {
    let mut config = EngineConfig::new(&cli.data_dir);
    if let (Some(pack), Some(signature)) = (&cli.rules_pack, &cli.rules_sig) {
        config.rules = RuleSource::Files {
            pack: pack.clone(),
            signature: signature.clone(),
        };
    }
    config
}

fn run(cli: Cli) -> Result<ExitCode, Box<dyn std::error::Error>> {
    match &cli.command {
        Command::Scan {
            paths,
            json,
            max_size,
            cross_volumes,
        } => scan(&cli, paths, *json, *max_size, *cross_volumes),
        Command::Selftest { json } => {
            let engine = Engine::new(engine_config(&cli))?;
            let report = engine.self_test();
            if *json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                for check in &report.checks {
                    let mark = if check.passed { "OK " } else { "CHYBA" };
                    println!("[{mark}] {}: {}", check.name, check.detail);
                }
                println!(
                    "Self-test {}",
                    if report.passed { "prošel" } else { "SELHAL" }
                );
            }
            Ok(if report.passed {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }
        Command::Info => {
            let engine = Engine::new(engine_config(&cli))?;
            engine.self_test();
            let value = serde_json::json!({
                "engine": engine.info(),
                "protection": engine.protection_summary(),
            });
            println!("{}", serde_json::to_string_pretty(&value)?);
            Ok(ExitCode::SUCCESS)
        }
        Command::Rules { command } => rules(command),
        Command::Fleet {
            command: FleetCommand::Activation { days, note, uses },
        } => {
            use antishield_core::fleet::{ACTIVATION_PREFIX, OneTimeCode};
            let code = OneTimeCode::generate(ACTIVATION_PREFIX)?;
            println!("Aktivační kód: {}", code.display());
            println!("Do schránky (SQL, ukládá se jen otisk kódu):");
            let note: String = note
                .chars()
                .filter(|c| !c.is_control())
                .take(200)
                .collect();
            println!(
                "insert into antishield_fleet.activations (code_hash, note, expires_at, uses_left) values \
                 (decode('{}', 'hex'), '{}', now() + interval '{} days', {});",
                code.digest_hex(),
                note.replace('\'', "''"),
                (*days).clamp(1, 730),
                (*uses).clamp(1, 100_000)
            );
            Ok(ExitCode::SUCCESS)
        }
        Command::Audit {
            command: AuditCommand::Verify,
        } => {
            let report = verify_dir(&cli.data_dir.join("audit"))?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(if report.ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }
    }
}

fn scan(
    cli: &Cli,
    paths: &[PathBuf],
    json: bool,
    max_size: Option<u64>,
    cross_volumes: bool,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let engine = Engine::new(engine_config(cli))?;
    let self_test = engine.self_test();
    if !self_test.passed {
        return Err("self-test selhal, kontrolu nespouštím".into());
    }
    let roots: Vec<PathBuf> = paths
        .iter()
        .map(std::path::absolute)
        .collect::<Result<_, _>>()?;
    let mut request = ScanRequest::new(roots);
    request.stay_on_volume = !cross_volumes;
    if let Some(limit) = max_size {
        request.limits.max_file_size_bytes = limit;
    }
    let (tx, rx) = mpsc::channel();
    let _handle = engine
        .start_scan(request, Arc::new(ChannelObserver(tx)))
        .map_err(|e| describe(&e))?;

    let mut summary: Option<ScanSummary> = None;
    for event in rx {
        match event {
            ScanEvent::Started { roots, .. } if !json => {
                eprintln!("Kontrola: {}", roots.join(", "));
            }
            ScanEvent::FindingDetected { finding, .. } if !json => {
                let kind = if finding.test_only {
                    " (testovací)"
                } else {
                    ""
                };
                println!(
                    "NÁLEZ{kind}: {} – {} [{}]",
                    finding.path, finding.rule_name, finding.rule_id
                );
            }
            ScanEvent::Finished { summary: s, .. } => {
                summary = Some(s);
                break;
            }
            _ => {}
        }
    }
    let summary = summary.ok_or("kontrola skončila bez souhrnu")?;
    if json {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        print_summary(&summary);
    }
    Ok(match (&summary.outcome, summary.findings.is_empty()) {
        (ScanOutcome::Completed, true) => ExitCode::SUCCESS,
        (ScanOutcome::Completed, false) => ExitCode::from(1),
        _ => ExitCode::from(2),
    })
}

fn describe(err: &EngineError) -> String {
    let dto = ErrorDto::from(err);
    format!("{} ({})", dto.message, dto.code)
}

fn print_summary(summary: &ScanSummary) {
    let outcome = match &summary.outcome {
        ScanOutcome::Completed => "dokončena".to_string(),
        ScanOutcome::Cancelled => "zrušena".to_string(),
        ScanOutcome::Failed { reason } => format!("selhala: {reason}"),
    };
    println!("Kontrola {outcome}.");
    println!(
        "Zkontrolováno souborů: {}, bajtů: {}, nálezů: {}, přeskočeno: {}, nerozbalených archivů: {}",
        summary.files_scanned,
        summary.bytes_scanned,
        summary.findings.len(),
        summary.skipped_total,
        summary.archives_not_inspected
    );
    for count in &summary.skipped_by_reason {
        println!("  přeskočeno ({}): {}", count.reason, count.count);
    }
    println!(
        "Pravidla: {} {}{}",
        summary.rule_pack.pack_id,
        summary.rule_pack.version,
        if summary.rule_pack.test_pack {
            " (testovací sada – nejde o úplnou antivirovou ochranu)"
        } else {
            ""
        }
    );
}

fn rules(command: &RulesCommand) -> Result<ExitCode, Box<dyn std::error::Error>> {
    match command {
        RulesCommand::Verify { pack, signature } => {
            let pack_bytes = std::fs::read(pack)?;
            let sig_bytes = std::fs::read(signature)?;
            let pack = RulePack::load(&pack_bytes, &sig_bytes, &builtin_trusted_keys(), now_unix())
                .map_err(|e| describe(&e))?;
            println!("{}", serde_json::to_string_pretty(pack.info())?);
            Ok(ExitCode::SUCCESS)
        }
        RulesCommand::Build {
            base,
            selftest,
            forge,
            sequence,
            version,
            valid_days,
            min_yara_rules,
            out,
        } => build_rules(
            base,
            selftest,
            forge,
            *sequence,
            version,
            *valid_days,
            *min_yara_rules,
            out,
        ),
        #[cfg(feature = "signing")]
        RulesCommand::Keygen { key_id, out_dir } => keygen(key_id, out_dir),
        #[cfg(feature = "signing")]
        RulesCommand::Sign {
            pack,
            key,
            key_id,
            out,
        } => sign(pack, key, key_id, out),
    }
}

#[allow(clippy::too_many_arguments)]
fn build_rules(
    base: &std::path::Path,
    selftest: &std::path::Path,
    forge_file: &std::path::Path,
    sequence: u64,
    version: &str,
    valid_days: i64,
    min_yara_rules: usize,
    out: &std::path::Path,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let base: serde_json::Value = serde_json::from_slice(&std::fs::read(base)?)?;
    let selftest = std::fs::read_to_string(selftest)?;
    let forge_text = std::fs::read_to_string(forge_file)?;
    let (pack, stats) = forge::build_pack(
        &base,
        &selftest,
        &forge_text,
        sequence,
        version,
        now_unix(),
        valid_days,
    )?;
    let total: usize = stats.included.iter().map(|(_, _, n)| n).sum();
    println!("Zdroje v sadě ({}):", stats.included.len());
    for (name, license, count) in &stats.included {
        println!("  {name}: {count} pravidel, licence {license}");
    }
    println!(
        "Vynecháno kvůli licenci ({}):",
        stats.excluded_license.len()
    );
    for (name, url) in &stats.excluded_license {
        println!("  {name} ({url})");
    }
    println!("Pravidla, která YARA-X nepřeložil: {}", stats.failed_rules);
    println!("Pravidel YARA celkem: {total}");
    if total < min_yara_rules {
        return Err(format!("too few YARA rules: {total} < {min_yara_rules}").into());
    }
    let mut text = serde_json::to_string_pretty(&pack)?;
    text.push('\n');
    std::fs::write(out, text)?;
    println!("Sada zapsána: {}", out.display());
    Ok(ExitCode::SUCCESS)
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

#[cfg(feature = "signing")]
fn keygen(key_id: &str, out_dir: &std::path::Path) -> Result<ExitCode, Box<dyn std::error::Error>> {
    use antishield_core::rules::signing;
    use std::io::Write;

    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| format!("random generator: {e}"))?;
    std::fs::create_dir_all(out_dir)?;
    let key_path = out_dir.join(format!("{key_id}.key"));
    let pub_path = out_dir.join(format!("{key_id}.pub.hex"));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut key_file = options.open(&key_path)?;
    writeln!(key_file, "{}", hex::encode(seed))?;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&pub_path)?
        .write_all(format!("{}\n", hex::encode(signing::public_key(&seed))).as_bytes())?;
    println!("Soukromý klíč: {} (necommitovat!)", key_path.display());
    println!("Veřejný klíč:  {}", pub_path.display());
    Ok(ExitCode::SUCCESS)
}

/// Klíč pro kontrolu nového podpisu se stejnými pravidly jako v aplikaci.
/// Klíč se jménem zabudovaného klíče musí být přesně ten zabudovaný (jinak by
/// aplikace podpis odmítla); neznámý klíč smí podepsat jen testovací sadu.
#[cfg(feature = "signing")]
fn signing_check_key(
    key_id: &str,
    public_key: [u8; 32],
) -> Result<antishield_core::rules::TrustedKey, String> {
    let builtin = builtin_trusted_keys()
        .into_iter()
        .find(|k| k.key_id == key_id);
    if let Some(known) = &builtin
        && known.public_key != public_key
    {
        return Err(format!(
            "the key file does not match the built-in key {key_id}"
        ));
    }
    Ok(antishield_core::rules::TrustedKey {
        key_id: key_id.to_string(),
        public_key,
        test_only: builtin.is_none_or(|k| k.test_only),
    })
}

#[cfg(all(test, feature = "signing"))]
mod sign_tests {
    use super::signing_check_key;
    use antishield_core::rules::builtin_trusted_keys;

    #[test]
    fn production_key_signs_production_packs() {
        let prod = builtin_trusted_keys()
            .into_iter()
            .find(|k| !k.test_only)
            .expect("production key is built in");
        let key = signing_check_key(&prod.key_id, prod.public_key).expect("matching key");
        assert!(!key.test_only);
    }

    #[test]
    fn wrong_or_unknown_keys_are_restricted() {
        let prod = builtin_trusted_keys()
            .into_iter()
            .find(|k| !k.test_only)
            .expect("production key is built in");
        assert!(signing_check_key(&prod.key_id, [7; 32]).is_err());
        let unknown = signing_check_key("someone-else", [7; 32]).expect("unknown key");
        assert!(unknown.test_only);
    }
}

#[cfg(feature = "signing")]
fn sign(
    pack: &std::path::Path,
    key: &std::path::Path,
    key_id: &str,
    out: &std::path::Path,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    use antishield_core::rules::signing;

    let seed: [u8; 32] = hex::decode(std::fs::read_to_string(key)?.trim())?
        .try_into()
        .map_err(|_| "the key file must contain 32 bytes in hex")?;
    let pack_bytes = std::fs::read(pack)?;
    let check_key = signing_check_key(key_id, signing::public_key(&seed))?;
    let signature = signing::sign_pack(&pack_bytes, &seed, key_id);
    // Kontrola: nová sada musí projít stejným ověřením jako v aplikaci.
    RulePack::load(&pack_bytes, signature.as_bytes(), &[check_key], now_unix())
        .map_err(|e| describe(&e))?;
    std::fs::write(out, signature)?;
    println!("Podpis zapsán: {}", out.display());
    Ok(ExitCode::SUCCESS)
}
