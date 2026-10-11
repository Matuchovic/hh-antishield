//! Kontrola jednoho souboru: otisky, vzory, YARA a obsah archivů ZIP
//! (na macOS i balíčků PKG a obrazů DMG). Používá ji koordinátor kontroly
//! i hlídání složek.

use std::io::{Cursor, Read};
use std::path::Path;

use crate::matcher::{ArchiveFormat, ContentMatcher, scan_buffer};
use crate::platform::{self, OpenError};
use crate::rules::RulePack;
use crate::types::{
    Evidence, FileIdentity, Finding, FindingOrigin, ScanLimits, Severity, SkipReason,
};

/// Velikost bloku při čtení.
pub const CHUNK_SIZE: usize = 1024 * 1024;
/// Obsah větší než tato mez se po kontrole uvolní, aby vlákno nedrželo paměť.
const KEEP_CONTENT_CAPACITY: usize = 8 * 1024 * 1024;
const MAX_META_LEN: usize = 300;
const MAX_ENTRY_NAME: usize = 300;

/// Ochrana proti „zip bombám“: počet položek, celková rozbalená velikost a poměr komprese.
const MAX_ZIP_ENTRIES: usize = 5_000;
const MAX_ZIP_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
const MAX_ZIP_RATIO: u64 = 200;

pub(crate) enum FileOutcome {
    Scanned {
        findings: Vec<Finding>,
        /// Archiv, jehož obsah se nepodařilo zkontrolovat celý.
        archive: bool,
        yara_incomplete: bool,
    },
    Skipped(SkipReason),
    Cancelled,
}

/// Zpětná vazba pro volajícího: zrušení a průběh čtení.
pub(crate) struct Hooks<'a> {
    pub stopped: &'a dyn Fn() -> bool,
    pub progress: &'a dyn Fn(u64),
}

/// Společný kontext jednoho souboru pro tvorbu nálezů.
struct Context<'a> {
    rules: &'a RulePack,
    path: &'a str,
    sha256: &'a str,
    identity: FileIdentity,
    changed: bool,
    origin: Option<&'a FindingOrigin>,
}

impl Context<'_> {
    fn classic(&self, rule_index: usize, evidence: Evidence, entry: Option<&str>) -> Finding {
        let rule = self.rules.rule(rule_index);
        Finding {
            path: self.path.to_string(),
            sha256: self.sha256.to_string(),
            rule_id: rule.id.clone(),
            rule_name: rule.name.clone(),
            rule_version: rule.version,
            rule_description: rule.description.cs.clone(),
            severity: rule.severity,
            test_only: rule.test_only,
            evidence: vec![evidence],
            identity: self.identity,
            changed_during_read: self.changed,
            archive_entry: entry.map(str::to_string),
            origin: self.origin.cloned(),
        }
    }

    /// Nález z pravidla YARA. Závažnost vychází z metadat `score` (0–100);
    /// pravidla s `hh_test_only = true` jsou jen testovací.
    fn yara(&self, rule: &yara_x::Rule<'_, '_>, entry: Option<&str>) -> Finding {
        use yara_x::MetaValue;
        let mut description = None;
        let mut author = None;
        let mut reference = None;
        let mut score = None;
        let mut test_marker = false;
        for (key, value) in rule.metadata() {
            match (key, value) {
                ("description", MetaValue::String(text)) => description = Some(meta_text(text)),
                ("author", MetaValue::String(text)) => author = Some(meta_text(text)),
                ("reference", MetaValue::String(text)) => reference = Some(meta_text(text)),
                ("score", MetaValue::Integer(value)) => score = Some(value),
                ("hh_test_only", MetaValue::Bool(true)) => test_marker = true,
                _ => {}
            }
        }
        let test_only = test_marker || self.rules.info().test_pack;
        let severity = if test_only {
            Severity::TestOnly
        } else {
            match score {
                Some(s) if s >= 80 => Severity::High,
                Some(s) if s >= 60 => Severity::Medium,
                Some(_) => Severity::Low,
                None => Severity::Medium,
            }
        };
        let namespace = rule.namespace().to_string();
        let identifier = rule.identifier().to_string();
        Finding {
            path: self.path.to_string(),
            sha256: self.sha256.to_string(),
            rule_id: format!("YARA:{namespace}:{identifier}"),
            rule_name: identifier.clone(),
            rule_version: 1,
            rule_description: description
                .unwrap_or_else(|| "Soubor odpovídá pravidlu YARA.".to_string()),
            severity,
            test_only,
            evidence: vec![Evidence::YaraMatch {
                source: namespace,
                rule: identifier,
                author,
                reference,
            }],
            identity: self.identity,
            changed_during_read: self.changed,
            archive_entry: entry.map(str::to_string),
            origin: self.origin.cloned(),
        }
    }
}

fn meta_text(value: &str) -> String {
    value.chars().take(MAX_META_LEN).collect()
}

/// Spustí YARA na data. `Err(())` = vypršel čas nebo chyba skeneru.
fn run_yara(
    scanner: &mut yara_x::Scanner<'_>,
    data: &[u8],
    ctx: &Context<'_>,
    entry: Option<&str>,
    out: &mut Vec<Finding>,
) -> Result<(), ()> {
    let results = scanner.scan(data).map_err(|_| ())?;
    for rule in results.matching_rules() {
        out.push(ctx.yara(&rule, entry));
    }
    Ok(())
}

/// Kontrola položek uvnitř archivu, balíčku nebo obrazu disku. Nálezy patří
/// vnějšímu souboru (cesta, otisk, identita) s názvem položky, takže je
/// karanténa izoluje celý.
pub(crate) struct ContainerScan<'a, 's> {
    ctx: &'a Context<'a>,
    limits: &'a ScanLimits,
    yara: Option<&'a mut yara_x::Scanner<'s>>,
    out: &'a mut Vec<Finding>,
}

impl ContainerScan<'_, '_> {
    /// Větší položky se nečtou (stejný limit jako u YARA).
    pub(crate) fn max_entry_bytes(&self) -> u64 {
        self.limits.max_yara_file_bytes
    }

    /// Zkontroluje data jedné položky; `false`, když ji nešlo zkontrolovat celou.
    pub(crate) fn entry(&mut self, name: &str, data: &[u8]) -> bool {
        let verdict = scan_buffer(self.ctx.rules, data, CHUNK_SIZE);
        for m in &verdict.matches {
            self.out.push(
                self.ctx
                    .classic(m.rule_index, m.evidence.clone(), Some(name)),
            );
        }
        let mut complete = true;
        if let Some(scanner) = self.yara.as_deref_mut()
            && run_yara(scanner, data, self.ctx, Some(name), self.out).is_err()
        {
            complete = false;
        }
        // Vnořené archivy se dál nerozbalují.
        if verdict.archive.is_some() {
            complete = false;
        }
        complete
    }
}

/// Zkontroluje obsah archivu ZIP v paměti. Vrací `false`, když obsah
/// nešlo projít celý (šifrování, limity, poškození, vnořené archivy).
fn inspect_zip(data: &[u8], scan: &mut ContainerScan<'_, '_>, hooks: &Hooks<'_>) -> bool {
    let Ok(mut archive) = zip::ZipArchive::new(Cursor::new(data)) else {
        return false;
    };
    if archive.len() > MAX_ZIP_ENTRIES {
        return false;
    }
    let limit = scan.max_entry_bytes();
    let mut complete = true;
    let mut total = 0u64;
    let mut entry_data = Vec::new();
    for index in 0..archive.len() {
        if (hooks.stopped)() {
            return false;
        }
        let Ok(mut entry) = archive.by_index(index) else {
            complete = false;
            continue;
        };
        if entry.is_dir() {
            continue;
        }
        let size = entry.size();
        let packed = entry.compressed_size().max(1);
        if size > limit
            || total.saturating_add(size) > MAX_ZIP_TOTAL_BYTES
            || (size > 1024 * 1024 && size / packed > MAX_ZIP_RATIO)
        {
            complete = false;
            continue;
        }
        let name: String = match entry.name() {
            Ok(name) => name.chars().take(MAX_ENTRY_NAME).collect(),
            Err(_) => format!("#{index}"),
        };
        entry_data.clear();
        // Skutečnou velikost hlídá i čtení: hlavička může lhát.
        let read = (&mut entry).take(limit + 1).read_to_end(&mut entry_data);
        if read.is_err() || entry_data.len() as u64 > limit {
            complete = false;
            continue;
        }
        total += entry_data.len() as u64;
        (hooks.progress)(0);
        if !scan.entry(&name, &entry_data) {
            complete = false;
        }
    }
    complete
}

/// Zkontroluje jeden soubor. Soubor se otevírá bez následování odkazů.
// Vstupy jsou oddělené záměrně: vyrovnávací paměti patří volajícímu vláknu.
#[allow(clippy::too_many_arguments)]
pub(crate) fn inspect_file(
    rules: &RulePack,
    limits: &ScanLimits,
    path: &Path,
    origin: Option<&FindingOrigin>,
    buffer: &mut [u8],
    content: &mut Vec<u8>,
    mut yara: Option<&mut yara_x::Scanner<'_>>,
    hooks: &Hooks<'_>,
) -> FileOutcome {
    let (mut file, meta) = match platform::open_regular(path) {
        Ok(opened) => opened,
        Err(OpenError::NotRegular) => return FileOutcome::Skipped(SkipReason::NotRegularFile),
        Err(OpenError::Io(err)) => return FileOutcome::Skipped(platform::classify_io_error(&err)),
    };
    let before = platform::identity(&meta);
    if before.size > limits.max_file_size_bytes {
        return FileOutcome::Skipped(SkipReason::TooLarge {
            size: before.size,
            limit: limits.max_file_size_bytes,
        });
    }

    // YARA a archivy potřebují celý obsah; soubory do limitu se drží v paměti.
    let mut collect = before.size <= limits.max_yara_file_bytes;
    content.clear();
    let mut matcher = ContentMatcher::new(rules);
    loop {
        if (hooks.stopped)() {
            return FileOutcome::Cancelled;
        }
        let read = match file.read(buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => return FileOutcome::Skipped(platform::classify_io_error(&err)),
        };
        matcher.feed(&buffer[..read]);
        if collect {
            if (content.len() + read) as u64 <= limits.max_yara_file_bytes {
                content.extend_from_slice(&buffer[..read]);
            } else {
                collect = false;
            }
        }
        (hooks.progress)(read as u64);
        if matcher.bytes_seen() > limits.max_file_size_bytes {
            return FileOutcome::Skipped(SkipReason::TooLarge {
                size: matcher.bytes_seen(),
                limit: limits.max_file_size_bytes,
            });
        }
    }

    let after = file.metadata().ok().map(|m| platform::identity(&m));
    let changed = matcher.bytes_seen() != before.size
        || after.is_none_or(|after| !platform::same_version(&before, &after));
    let verdict = matcher.finish();
    let sha256 = hex::encode(verdict.sha256);
    let display = path.display().to_string();
    let complete_in_memory = collect && content.len() as u64 == verdict.size;
    let ctx = Context {
        rules,
        path: &display,
        sha256: &sha256,
        identity: before,
        changed,
        origin,
    };
    let mut findings: Vec<Finding> = verdict
        .matches
        .iter()
        .map(|m| ctx.classic(m.rule_index, m.evidence.clone(), None))
        .collect();

    let mut yara_incomplete = false;
    if let Some(scanner) = yara.as_deref_mut() {
        if (hooks.stopped)() {
            return FileOutcome::Cancelled;
        }
        (hooks.progress)(0);
        if !complete_in_memory || run_yara(scanner, content, &ctx, None, &mut findings).is_err() {
            yara_incomplete = true;
        }
    }

    let mut archive_incomplete = verdict.archive.is_some();
    let mut scan = ContainerScan {
        ctx: &ctx,
        limits,
        yara,
        out: &mut findings,
    };
    match verdict.archive {
        Some(ArchiveFormat::Zip) if complete_in_memory => {
            archive_incomplete = !inspect_zip(content, &mut scan, hooks);
        }
        // Balíčky a obrazy disků macOS: jen nezměněný soubor (karanténa ověří otisk).
        #[cfg(target_os = "macos")]
        Some(format @ (ArchiveFormat::Dmg | ArchiveFormat::Xar)) if !changed => {
            archive_incomplete =
                !crate::container::inspect(path, format, verdict.size, &mut scan, hooks);
        }
        _ => {}
    }

    if content.capacity() > KEEP_CONTENT_CAPACITY {
        *content = Vec::new();
    }
    FileOutcome::Scanned {
        findings,
        archive: archive_incomplete,
        yara_incomplete,
    }
}

/// Kontrola jednotlivých souborů mimo velkou kontrolu (hlídání složek).
/// Drží si vlastní skener YARA a vyrovnávací paměti.
pub struct FileInspector<'r> {
    rules: &'r RulePack,
    limits: ScanLimits,
    yara: Option<yara_x::Scanner<'r>>,
    buffer: Vec<u8>,
    content: Vec<u8>,
}

/// Výsledek kontroly jednoho souboru.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InspectResult {
    Scanned {
        findings: Vec<Finding>,
        complete: bool,
    },
    Skipped(SkipReason),
}

impl std::fmt::Debug for FileInspector<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileInspector")
            .field("yara", &self.yara.is_some())
            .finish()
    }
}

impl<'r> FileInspector<'r> {
    pub fn new(rules: &'r RulePack, limits: ScanLimits) -> Self {
        let yara = rules.yara().map(|compiled| {
            let mut scanner = yara_x::Scanner::new(compiled);
            scanner.set_timeout(std::time::Duration::from_millis(limits.yara_timeout_ms));
            scanner
        });
        Self {
            rules,
            limits,
            yara,
            buffer: vec![0u8; CHUNK_SIZE],
            content: Vec::new(),
        }
    }

    pub fn inspect(&mut self, path: &Path) -> InspectResult {
        let hooks = Hooks {
            stopped: &|| false,
            progress: &|_| {},
        };
        match inspect_file(
            self.rules,
            &self.limits,
            path,
            None,
            &mut self.buffer,
            &mut self.content,
            self.yara.as_mut(),
            &hooks,
        ) {
            FileOutcome::Scanned {
                findings,
                archive,
                yara_incomplete,
            } => InspectResult::Scanned {
                findings,
                complete: !archive && !yara_incomplete,
            },
            FileOutcome::Skipped(reason) => InspectResult::Skipped(reason),
            FileOutcome::Cancelled => InspectResult::Skipped(SkipReason::InternalError {
                message: "cancelled".into(),
            }),
        }
    }
}
