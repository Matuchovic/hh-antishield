//! Nastavení aplikace. Ukládá se jako JSON v datech aplikace; při načtení
//! i při uložení z rozhraní se ověřuje, nevalidní hodnoty se nepřijmou.

use std::path::{Path, PathBuf};

use antishield_core::error::ErrorDto;
use antishield_core::system::default_watch_folders;
use serde::{Deserialize, Serialize};

const MAX_WATCH_FOLDERS: usize = 32;
const MAX_FILE: u64 = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Schedule {
    Off,
    Daily,
    Weekly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PresetScan {
    Quick,
    Full,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Settings {
    /// Hlídání složek (kontrola nových a změněných souborů).
    pub protection_enabled: bool,
    pub watch_folders: Vec<String>,
    /// Nález z hlídání rovnou přesunout do karantény.
    pub auto_quarantine: bool,
    pub notifications: bool,
    pub rules_auto_update: bool,
    pub schedule: Schedule,
    /// Hodina plánované kontroly (místní čas), 0–23.
    pub schedule_hour: u8,
    /// Den týdne pro týdenní kontrolu: 1 = pondělí … 7 = neděle.
    pub schedule_weekday: u8,
    pub schedule_scan: PresetScan,
    pub sounds: bool,
    pub intro: bool,
    pub reduced_motion: bool,
    pub launch_at_login: bool,
    /// Zavření okna aplikaci neukončí, ochrana běží dál (ikona v liště).
    pub keep_running_in_background: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            protection_enabled: true,
            watch_folders: default_watch_folders()
                .into_iter()
                .map(|p| p.display().to_string())
                .collect(),
            auto_quarantine: true,
            notifications: true,
            rules_auto_update: true,
            schedule: Schedule::Weekly,
            schedule_hour: 12,
            schedule_weekday: 3,
            schedule_scan: PresetScan::Quick,
            sounds: true,
            intro: true,
            reduced_motion: false,
            launch_at_login: true,
            keep_running_in_background: true,
        }
    }
}

fn invalid(message: &str) -> ErrorDto {
    ErrorDto {
        code: "invalid_settings".into(),
        message: message.into(),
    }
}

impl Settings {
    /// Ověří hodnoty z rozhraní.
    pub fn validate(&self) -> Result<(), ErrorDto> {
        if self.schedule_hour > 23 {
            return Err(invalid("schedule hour must be 0-23"));
        }
        if !(1..=7).contains(&self.schedule_weekday) {
            return Err(invalid("schedule weekday must be 1-7"));
        }
        if self.watch_folders.len() > MAX_WATCH_FOLDERS {
            return Err(invalid("too many watched folders"));
        }
        for folder in &self.watch_folders {
            let path = Path::new(folder);
            if !path.is_absolute() || folder.len() > 1024 {
                return Err(invalid("watched folders must be absolute paths"));
            }
        }
        Ok(())
    }

    pub fn watch_paths(&self) -> Vec<PathBuf> {
        self.watch_folders.iter().map(PathBuf::from).collect()
    }

    /// Načte nastavení; poškozený nebo chybějící soubor = výchozí hodnoty.
    pub fn load(path: &Path) -> Self {
        let loaded = std::fs::metadata(path)
            .ok()
            .filter(|m| m.len() <= MAX_FILE)
            .and_then(|_| std::fs::read(path).ok())
            .and_then(|bytes| serde_json::from_slice::<Settings>(&bytes).ok());
        match loaded {
            Some(settings) if settings.validate().is_ok() => settings,
            _ => Self::default(),
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), ErrorDto> {
        self.validate()?;
        let io = |e: std::io::Error| ErrorDto {
            code: "io".into(),
            message: e.to_string(),
        };
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(io)?;
        }
        let temp = path.with_extension("json.tmp");
        let text = serde_json::to_vec_pretty(self).map_err(|e| invalid(&e.to_string()))?;
        std::fs::write(&temp, text).map_err(io)?;
        std::fs::rename(&temp, path).map_err(io)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn invalid_values_are_rejected_and_bad_files_fall_back() {
        let mut settings = Settings::default();
        assert!(settings.validate().is_ok());
        settings.schedule_hour = 24;
        assert!(settings.validate().is_err());
        let settings = Settings {
            watch_folders: vec!["relative/path".into()],
            ..Settings::default()
        };
        assert!(settings.validate().is_err());

        let dir = std::env::temp_dir().join(format!("as-settings-{}", std::process::id()));
        let path = dir.join("settings.json");
        let custom = Settings {
            sounds: false,
            ..Settings::default()
        };
        custom.save(&path).unwrap();
        assert_eq!(Settings::load(&path), custom);
        std::fs::write(&path, b"{ broken").unwrap();
        assert_eq!(Settings::load(&path), Settings::default());
        let _ = std::fs::remove_dir_all(dir);
    }
}
