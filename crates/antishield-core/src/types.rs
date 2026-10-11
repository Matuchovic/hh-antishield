//! Veřejné datové typy. Jsou to čistá data bez ukazatelů, takže je jde poslat
//! přes IPC (Tauri) nebo později přes XPC beze změny.

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Limity jedné kontroly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanLimits {
    /// Soubory větší než limit se nečtou a ve výsledku jsou jako přeskočené.
    pub max_file_size_bytes: u64,
    /// Když čtení souboru tak dlouho nepokročí, označí se jako zaseknuté.
    pub stall_timeout_ms: u64,
    /// Maximální hloubka adresářů pod kořenem.
    pub max_depth: usize,
    /// Počet pracovních vláken.
    pub worker_threads: usize,
    /// Pravidla YARA dostanou soubory do této velikosti (celý obsah je v paměti).
    pub max_yara_file_bytes: u64,
    /// Nejdelší doba kontroly jednoho souboru pravidly YARA.
    pub yara_timeout_ms: u64,
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            max_file_size_bytes: 4 * 1024 * 1024 * 1024,
            stall_timeout_ms: 30_000,
            max_depth: 64,
            max_yara_file_bytes: 32 * 1024 * 1024,
            yara_timeout_ms: 20_000,
            worker_threads: std::thread::available_parallelism()
                .map(|n| n.get().saturating_sub(1).clamp(2, 4))
                .unwrap_or(2),
        }
    }
}

/// Požadavek na kontrolu.
#[derive(Debug, Clone)]
pub struct ScanRequest {
    /// Kořeny kontroly (soubory nebo složky) vybrané uživatelem.
    pub roots: Vec<PathBuf>,
    /// Nepřecházet na jiné svazky pod kořenem.
    pub stay_on_volume: bool,
    pub limits: ScanLimits,
    /// Odkud cíl pochází (proces, položka po spuštění). Klíčem je kanonická cesta souboru.
    pub origins: HashMap<PathBuf, FindingOrigin>,
}

impl ScanRequest {
    pub fn new(roots: Vec<PathBuf>) -> Self {
        Self {
            roots,
            stay_on_volume: true,
            limits: ScanLimits::default(),
            origins: HashMap::new(),
        }
    }
}

/// Souvislost nálezu: běžící proces nebo položka spouštěná po přihlášení.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum FindingOrigin {
    Process { pid: u32, name: String },
    StartupItem { location: String, label: String },
}

/// Závažnost pravidla.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Testovací detekce (EICAR, syntetické vzorky). Nejde o škodlivý software.
    TestOnly,
    Low,
    Medium,
    High,
    Critical,
}

/// Důkaz, proč pravidlo soubor označilo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum Evidence {
    /// SHA-256 celého souboru se přesně shoduje s indikátorem.
    Sha256Match { digest_hex: String },
    /// Soubor obsahuje bajtový vzor pravidla.
    BytePattern { offset: u64, length: u32 },
    /// Soubor odpovídá oficiální definici testovacího souboru EICAR.
    EicarStandard,
    /// Soubor splnil podmínky pravidla YARA.
    YaraMatch {
        /// Zdroj pravidel (jmenný prostor), viz `RulePackInfo::sources`.
        source: String,
        rule: String,
        author: Option<String>,
        reference: Option<String>,
    },
}

/// Identita souboru v okamžiku čtení. Slouží k odhalení změny během kontroly
/// a později k ověření, že karanténa míří na stejný soubor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct FileIdentity {
    /// Zařízení (na Windows ve v0.1 vždy 0).
    pub device: u64,
    /// Inode (na Windows ve v0.1 vždy 0).
    pub inode: u64,
    pub size: u64,
    pub modified_sec: i64,
    pub modified_nsec: u32,
    pub changed_sec: i64,
    pub changed_nsec: u32,
}

/// Jeden nález.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub path: String,
    pub sha256: String,
    pub rule_id: String,
    pub rule_name: String,
    pub rule_version: u32,
    /// Popis pravidla v jazyce enginu (čeština).
    pub rule_description: String,
    pub severity: Severity,
    /// Testovací detekce, ne skutečný škodlivý software.
    pub test_only: bool,
    pub evidence: Vec<Evidence>,
    pub identity: FileIdentity,
    /// Soubor se během čtení změnil, nález nemusí odpovídat aktuálnímu obsahu.
    pub changed_during_read: bool,
    /// Cesta uvnitř archivu, pokud nález pochází z jeho obsahu.
    pub archive_entry: Option<String>,
    pub origin: Option<FindingOrigin>,
}

/// Proč položka nebyla zkontrolována.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum SkipReason {
    /// Symbolický odkaz nebo jiný bod přesměrování; nesledujeme ho.
    Symlink,
    /// FIFO, socket, zařízení a podobně.
    NotRegularFile,
    TooLarge {
        size: u64,
        limit: u64,
    },
    /// Soubor není stažený z cloudu (iCloud, OneDrive); kontrola by ho stáhla.
    NotDownloaded,
    /// Jiný nebo síťový svazek.
    OtherVolume,
    PermissionDenied,
    /// Soubor mezitím zmizel.
    NotFound,
    /// Čtení dlouho nepokročilo.
    Timeout {
        limit_ms: u64,
    },
    ReadError {
        code: Option<i32>,
        message: String,
    },
    InternalError {
        message: String,
    },
}

impl SkipReason {
    /// Stabilní kód pro souhrn podle důvodu.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Symlink => "symlink",
            Self::NotRegularFile => "notRegularFile",
            Self::TooLarge { .. } => "tooLarge",
            Self::NotDownloaded => "notDownloaded",
            Self::OtherVolume => "otherVolume",
            Self::PermissionDenied => "permissionDenied",
            Self::NotFound => "notFound",
            Self::Timeout { .. } => "timeout",
            Self::ReadError { .. } => "readError",
            Self::InternalError { .. } => "internalError",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SkippedItem {
    pub path: String,
    pub reason: SkipReason,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SkipCount {
    pub reason: String,
    pub count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanProgress {
    pub files_scanned: u64,
    pub bytes_scanned: u64,
    pub items_skipped: u64,
    pub findings: u64,
    pub current_path: Option<String>,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum ScanOutcome {
    Completed,
    Cancelled,
    Failed { reason: String },
}

/// Informace o načtené sadě pravidel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RulePackInfo {
    pub pack_id: String,
    pub version: String,
    pub sequence: u64,
    pub rule_count: u32,
    pub signing_key_id: String,
    pub test_pack: bool,
    pub created_at_unix: i64,
    pub expires_at_unix: i64,
    pub expired: bool,
    /// Kolik z `rule_count` jsou pravidla YARA.
    pub yara_rule_count: u32,
    /// Zdroje pravidel YARA s licencí (atribuce autorům).
    pub sources: Vec<RuleSourceInfo>,
}

/// Zdroj pravidel YARA v sadě.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleSourceInfo {
    pub id: String,
    pub name: String,
    pub url: String,
    pub license: String,
    pub rule_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanSummary {
    pub scan_id: String,
    pub outcome: ScanOutcome,
    pub roots: Vec<String>,
    pub started_at_ms: u64,
    pub finished_at_ms: u64,
    pub files_scanned: u64,
    pub bytes_scanned: u64,
    /// Archivy se ve v0.1 nerozbalují; tolik jich bylo zkontrolováno jen jako celek.
    pub archives_not_inspected: u64,
    /// Soubory zkontrolované jen otisky a vzory, bez pravidel YARA
    /// (větší než limit nebo kontrola YARA nedoběhla).
    pub yara_incomplete: u64,
    pub findings: Vec<Finding>,
    pub skipped_total: u64,
    pub skipped_by_reason: Vec<SkipCount>,
    /// Prvních nejvýš 100 přeskočených položek.
    pub skipped_sample: Vec<SkippedItem>,
    pub rule_pack: RulePackInfo,
    pub engine_version: String,
}

/// Událost kontroly. Pořadí je zaručené: `Started`, libovolně `Progress`
/// a `FindingDetected`, nakonec přesně jednou `Finished`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum ScanEvent {
    Started {
        scan_id: String,
        roots: Vec<String>,
    },
    Progress {
        scan_id: String,
        progress: ScanProgress,
    },
    FindingDetected {
        scan_id: String,
        finding: Finding,
    },
    Finished {
        scan_id: String,
        summary: ScanSummary,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EngineInfo {
    pub engine_version: String,
    pub platform: String,
    pub rule_pack: RulePackInfo,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SelfTestCheck {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SelfTestReport {
    pub passed: bool,
    pub ran_at_ms: u64,
    pub checks: Vec<SelfTestCheck>,
}

/// Záznam auditního logu pro zobrazení.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEvent {
    pub seq: u64,
    pub ts_ms: u64,
    pub kind: String,
    pub data: serde_json::Value,
}
