//! Pravdivý stav ochrany.
//!
//! Každá komponenta hlásí svůj stav sama. Souhrnnou úroveň počítá jediná čistá
//! funkce [`summarize_protection`]: „chráněno“ vrátí jen tehdy, když běží
//! a je ověřená ochrana v reálném čase i aktualizace. Ve v0.1 to nenastane nikdy.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ComponentKind {
    DetectionEngine,
    RulePack,
    AuditLog,
    OnDemandScan,
    RealTimeProtection,
    WebProtection,
    EmailProtection,
    PrivacyProtection,
    Quarantine,
    Updates,
    SystemCare,
}

impl ComponentKind {
    pub const ALL: [ComponentKind; 11] = [
        Self::DetectionEngine,
        Self::RulePack,
        Self::AuditLog,
        Self::OnDemandScan,
        Self::RealTimeProtection,
        Self::WebProtection,
        Self::EmailProtection,
        Self::PrivacyProtection,
        Self::Quarantine,
        Self::Updates,
        Self::SystemCare,
    ];
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum ComponentState {
    /// Funkce v této verzi neexistuje.
    NotImplemented,
    Disabled,
    /// Běží; `verified_at_ms` je čas posledního ověření.
    Running {
        verified_at_ms: u64,
    },
    Degraded {
        reason: String,
    },
    Failed {
        reason: String,
    },
}

impl ComponentState {
    pub fn is_running(&self) -> bool {
        matches!(self, Self::Running { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ComponentStatus {
    pub kind: ComponentKind,
    pub state: ComponentState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ProtectionLevel {
    /// Engine nebo pravidla nejsou připravené.
    NotReady,
    /// Funguje jen ruční kontrola.
    ManualScanOnly,
    /// Hlídání souborů a aktualizace pravidel běží, spouštění programů se
    /// ale neblokuje (bez Endpoint Security / ovladače).
    Monitored,
    /// Plná ochrana: navíc blokování na úrovni systému (webová ochrana).
    /// Ve verzi 0.2 nedosažitelné, protože webová ochrana není hotová.
    Protected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtectionSummary {
    pub level: ProtectionLevel,
    pub components: Vec<ComponentStatus>,
}

/// Jediné místo, které rozhoduje o souhrnném stavu.
pub fn summarize_protection(components: &[ComponentStatus]) -> ProtectionLevel {
    let running = |kind: ComponentKind| {
        components
            .iter()
            .any(|c| c.kind == kind && c.state.is_running())
    };
    let ready = running(ComponentKind::DetectionEngine)
        && running(ComponentKind::RulePack)
        && running(ComponentKind::OnDemandScan);
    if !ready {
        return ProtectionLevel::NotReady;
    }
    if !(running(ComponentKind::RealTimeProtection) && running(ComponentKind::Updates)) {
        return ProtectionLevel::ManualScanOnly;
    }
    if running(ComponentKind::WebProtection) {
        ProtectionLevel::Protected
    } else {
        ProtectionLevel::Monitored
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn states() -> Vec<ComponentState> {
        vec![
            ComponentState::NotImplemented,
            ComponentState::Disabled,
            ComponentState::Running { verified_at_ms: 1 },
            ComponentState::Degraded { reason: "x".into() },
            ComponentState::Failed { reason: "x".into() },
        ]
    }

    /// Projde všechny kombinace stavů klíčových komponent.
    #[test]
    fn protected_only_with_realtime_updates_and_web() {
        let keys = [
            ComponentKind::DetectionEngine,
            ComponentKind::RulePack,
            ComponentKind::OnDemandScan,
            ComponentKind::RealTimeProtection,
            ComponentKind::Updates,
            ComponentKind::WebProtection,
        ];
        let all = states();
        let total = all.len().pow(keys.len() as u32);
        for combination in 0..total {
            let mut n = combination;
            let components: Vec<ComponentStatus> = keys
                .iter()
                .map(|kind| {
                    let state = all[n % all.len()].clone();
                    n /= all.len();
                    ComponentStatus { kind: *kind, state }
                })
                .collect();
            let level = summarize_protection(&components);
            let rt = components[3].state.is_running();
            let updates = components[4].state.is_running();
            let web = components[5].state.is_running();
            if level == ProtectionLevel::Protected {
                assert!(
                    rt && updates && web,
                    "protected without all layers: {components:?}"
                );
            }
            if level == ProtectionLevel::Monitored {
                assert!(
                    rt && updates && !web,
                    "monitored without watch/updates: {components:?}"
                );
            }
            let ready = components[..3].iter().all(|c| c.state.is_running());
            assert_eq!(level == ProtectionLevel::NotReady, !ready);
        }
    }

    #[test]
    fn version_01_is_manual_scan_only() {
        let components: Vec<ComponentStatus> = ComponentKind::ALL
            .iter()
            .map(|kind| ComponentStatus {
                kind: *kind,
                state: match kind {
                    ComponentKind::DetectionEngine
                    | ComponentKind::RulePack
                    | ComponentKind::AuditLog
                    | ComponentKind::OnDemandScan => ComponentState::Running { verified_at_ms: 1 },
                    _ => ComponentState::NotImplemented,
                },
            })
            .collect();
        assert_eq!(
            summarize_protection(&components),
            ProtectionLevel::ManualScanOnly
        );
    }
}
