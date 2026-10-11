//! Obsah instalačních balíčků a obrazů disků macOS (PKG, DMG). Balíček se
//! rozbalí nástrojem `pkgutil`, obraz se připojí jen pro čtení a bez ikony ve
//! Finderu (`hdiutil`), obojí do soukromé dočasné složky. Každý soubor uvnitř
//! se zkontroluje stejně jako položka archivu ZIP; nález patří vnějšímu
//! souboru, takže ho karanténa izoluje celý. Šifrované obrazy, obrazy
//! s licencí a obsah nad limity se jen označí jako nezkontrolované.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::inspect::{ContainerScan, Hooks};
use crate::matcher::ArchiveFormat;

/// Větší balíčky a obrazy se nerozbalují (místo na disku, čas).
const MAX_PKG_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_DMG_BYTES: u64 = 4 * 1024 * 1024 * 1024;
/// Limity obsahu: počet souborů, celkem přečtených bajtů a čas.
const MAX_FILES: usize = 20_000;
const MAX_TOTAL_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_DURATION: Duration = Duration::from_secs(180);
/// Rozbalení nebo připojení nesmí viset.
const TOOL_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_ENTRY_NAME: usize = 300;

/// Dočasná složka jen pro tento proces; po kontrole se odpojí a smaže.
struct Workspace {
    dir: PathBuf,
    mounted: bool,
}

impl Workspace {
    fn create() -> Option<Self> {
        use std::os::unix::fs::DirBuilderExt;
        let dir = std::env::temp_dir().join(format!("antishield-{}", uuid::Uuid::new_v4()));
        std::fs::DirBuilder::new().mode(0o700).create(&dir).ok()?;
        Some(Self {
            dir,
            mounted: false,
        })
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        if self.mounted {
            let mut detach = Command::new("/usr/bin/hdiutil");
            detach.args(["detach", "-force", "-quiet"]).arg(&self.dir);
            let _ = run(detach, Duration::from_secs(60));
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Spustí nástroj s časovým limitem; `Some(stdout)` jen při úspěchu.
fn run(mut command: Command, timeout: Duration) -> Option<String> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut out = String::new();
                if let Some(mut stdout) = child.stdout.take() {
                    use std::io::Read;
                    let _ = stdout.read_to_string(&mut out);
                }
                return status.success().then_some(out);
            }
            Ok(None) if started.elapsed() < timeout => {
                std::thread::sleep(Duration::from_millis(50))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

/// Rozbalí balíček, nebo připojí obraz. `None`, když to nejde (šifrování,
/// licence, poškození, limity).
fn expand(path: &Path, format: ArchiveFormat, size: u64) -> Option<(Workspace, PathBuf)> {
    match format {
        ArchiveFormat::Xar if size <= MAX_PKG_BYTES => {
            let workspace = Workspace::create()?;
            let root = workspace.dir.join("pkg");
            let mut expand = Command::new("/usr/sbin/pkgutil");
            expand.arg("--expand-full").arg(path).arg(&root);
            run(expand, TOOL_TIMEOUT)?;
            Some((workspace, root))
        }
        ArchiveFormat::Dmg if size <= MAX_DMG_BYTES => {
            let mut check = Command::new("/usr/bin/hdiutil");
            check.arg("isencrypted").arg(path);
            if run(check, TOOL_TIMEOUT)?.contains("encrypted: YES") {
                return None;
            }
            let mut workspace = Workspace::create()?;
            let mut attach = Command::new("/usr/bin/hdiutil");
            attach
                .args([
                    "attach",
                    "-readonly",
                    "-nobrowse",
                    "-noautoopen",
                    "-quiet",
                    "-mountpoint",
                ])
                .arg(&workspace.dir)
                .arg(path);
            // Odpojit i po vypršení času (obraz mohl být mezitím připojen).
            workspace.mounted = true;
            run(attach, TOOL_TIMEOUT)?;
            let root = workspace.dir.clone();
            Some((workspace, root))
        }
        _ => None,
    }
}

/// Zkontroluje obsah balíčku nebo obrazu disku. Vrací `false`, když obsah
/// nešlo projít celý.
pub(crate) fn inspect(
    path: &Path,
    format: ArchiveFormat,
    size: u64,
    scan: &mut ContainerScan<'_, '_>,
    hooks: &Hooks<'_>,
) -> bool {
    let Some((_workspace, root)) = expand(path, format, size) else {
        return false;
    };
    let started = Instant::now();
    let mut complete = true;
    let mut files = 0usize;
    let mut total = 0u64;
    for entry in walkdir::WalkDir::new(&root).follow_links(false) {
        if (hooks.stopped)() || started.elapsed() > MAX_DURATION {
            return false;
        }
        let Ok(entry) = entry else {
            complete = false;
            continue;
        };
        if !entry.file_type().is_file() {
            continue;
        }
        files += 1;
        let Ok(meta) = entry.metadata() else {
            complete = false;
            continue;
        };
        if files > MAX_FILES || total.saturating_add(meta.len()) > MAX_TOTAL_BYTES {
            return false;
        }
        if meta.len() > scan.max_entry_bytes() {
            complete = false;
            continue;
        }
        let Ok(data) = std::fs::read(entry.path()) else {
            complete = false;
            continue;
        };
        total += data.len() as u64;
        (hooks.progress)(0);
        let name: String = entry
            .path()
            .strip_prefix(&root)
            .unwrap_or(entry.path())
            .display()
            .to_string()
            .chars()
            .take(MAX_ENTRY_NAME)
            .collect();
        if !scan.entry(&name, &data) {
            complete = false;
        }
    }
    complete
}
