//! Příběh útoku a radar ochrany.
//!
//! Příběh vzniká v okamžiku nálezu: původ souboru a řetěz spuštění se musí
//! přečíst dřív, než se soubor izoluje a proces ukončí. Ukládá se, aby přežil
//! restart, ale slouží jen k zobrazení; o zásahu nikdy nerozhoduje (nález
//! z uloženého příběhu se před vyčištěním znovu zkontroluje).
//!
//! Radar dostává souhrny skutečných kontrol (žádná vymyšlená aktivita): kolik
//! čeho hlídání zkontrolovalo a pár názvů jako ukázku.

use std::collections::VecDeque;
use std::io::Read;
use std::path::Path;

use antishield_core::Finding;
use antishield_core::provenance::Provenance;
use antishield_core::system::ProcessLink;
use serde::{Deserialize, Serialize};

const STORIES_FILE: &str = "stories.json";
const MAX_STORIES: usize = 100;
const MAX_STORIES_BYTES: u64 = 8 * 1024 * 1024;
/// Kolik posledních zkontrolovaných položek si radar pamatuje pro přehled.
const MAX_RECENT: usize = 30;
/// Kolik názvů jedna událost radaru nese jako ukázku.
pub const MAX_SAMPLES: usize = 6;

/// Kde hrozbu AntiShield zachytil.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum StorySource {
    /// Hlídání složek (nový nebo změněný soubor).
    Realtime,
    /// Běžící program.
    Program,
    /// Program spouštěný po přihlášení.
    Startup,
    /// Ruční nebo plánovaná kontrola.
    Scan,
}

/// Jak to skončilo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum StoryOutcome {
    Quarantined {
        item_id: String,
        process_terminated: bool,
    },
    /// Nahlášeno, čeká na rozhodnutí uživatele.
    Reported,
    Failed {
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Story {
    pub id: String,
    pub detected_at_ms: u64,
    pub source: StorySource,
    pub finding: Finding,
    pub provenance: Provenance,
    /// Proces a kdo ho spustil (jen u běžících programů).
    pub chain: Vec<ProcessLink>,
    pub outcome: StoryOutcome,
    pub updated_at_ms: u64,
}

/// Uložené příběhy, nejnovější první.
#[derive(Debug, Default)]
pub struct StoryBook {
    stories: VecDeque<Story>,
}

impl StoryBook {
    pub fn load(data_dir: &Path) -> Self {
        let mut bytes = Vec::new();
        let read = std::fs::File::open(data_dir.join(STORIES_FILE))
            .and_then(|file| file.take(MAX_STORIES_BYTES + 1).read_to_end(&mut bytes));
        let stories = match read {
            Ok(len) if (len as u64) <= MAX_STORIES_BYTES => {
                serde_json::from_slice::<Vec<Story>>(&bytes).unwrap_or_default()
            }
            _ => Vec::new(),
        };
        Self {
            stories: stories.into_iter().take(MAX_STORIES).collect(),
        }
    }

    fn save(&self, data_dir: &Path) {
        let Ok(bytes) = serde_json::to_vec(&self.stories) else {
            return;
        };
        let path = data_dir.join(STORIES_FILE);
        let tmp = path.with_extension("json.tmp");
        if std::fs::write(&tmp, bytes).is_ok() {
            let _ = std::fs::rename(&tmp, &path);
        }
    }

    /// Přidá příběh; stejný soubor se stejným obsahem se nezdvojuje.
    pub fn add(&mut self, story: Story, data_dir: &Path) {
        if let Some(existing) = self
            .stories
            .iter_mut()
            .find(|s| same_threat(s, &story.finding))
        {
            existing.outcome = story.outcome;
            existing.updated_at_ms = story.updated_at_ms;
            if existing.chain.is_empty() {
                existing.chain = story.chain;
            }
        } else {
            self.stories.push_front(story);
            self.stories.truncate(MAX_STORIES);
        }
        self.save(data_dir);
    }

    /// Po ručním vyčištění zapíše výsledek k příběhům stejného souboru.
    pub fn record_outcome(
        &mut self,
        path: &str,
        outcome: StoryOutcome,
        at_ms: u64,
        data_dir: &Path,
    ) {
        let mut changed = false;
        for story in self.stories.iter_mut().filter(|s| s.finding.path == path) {
            if !matches!(story.outcome, StoryOutcome::Quarantined { .. }) {
                story.outcome = outcome.clone();
                story.updated_at_ms = at_ms;
                changed = true;
            }
        }
        if changed {
            self.save(data_dir);
        }
    }

    pub fn list(&self) -> Vec<Story> {
        self.stories.iter().cloned().collect()
    }

    /// Cesty uložených nálezů, které ještě nejsou vyřešené (k novému ověření).
    pub fn unresolved_paths(&self, paths: &[String]) -> Vec<String> {
        self.stories
            .iter()
            .filter(|s| !matches!(s.outcome, StoryOutcome::Quarantined { .. }))
            .map(|s| s.finding.path.clone())
            .filter(|path| paths.contains(path))
            .collect()
    }
}

fn same_threat(story: &Story, finding: &Finding) -> bool {
    story.finding.path == finding.path && story.finding.sha256 == finding.sha256
}

/// Co radar ukazuje.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ActivityKind {
    Download,
    File,
    Mail,
    Program,
    Startup,
}

impl ActivityKind {
    /// Druh podle umístění souboru.
    pub fn for_path(path: &Path) -> Self {
        let text = path.to_string_lossy();
        if text.contains("/Library/Mail/") || text.contains("/Library/Containers/com.apple.mail/") {
            Self::Mail
        } else if text.contains("/LaunchAgents/")
            || text.contains("/LaunchDaemons/")
            || text.contains("\\Start Menu\\Programs\\Startup\\")
        {
            Self::Startup
        } else if path
            .components()
            .any(|c| c.as_os_str() == "Downloads" || c.as_os_str() == "Stažené soubory")
        {
            Self::Download
        } else {
            Self::File
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivitySample {
    pub name: String,
    pub threat: bool,
}

/// Jedna dávka skutečných kontrol pro radar.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Activity {
    pub at_ms: u64,
    pub kind: ActivityKind,
    /// Kolik položek dávka představuje (ukázka je jen část).
    pub count: u32,
    pub samples: Vec<ActivitySample>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecentCheck {
    pub at_ms: u64,
    pub kind: ActivityKind,
    pub name: String,
    pub threat: bool,
}

/// Počty kontrol od spuštění a poslední zkontrolované položky.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivityLog {
    pub since_ms: Option<u64>,
    pub downloads: u64,
    pub files: u64,
    pub mail: u64,
    pub programs: u64,
    pub startup: u64,
    pub threats: u64,
    pub recent: VecDeque<RecentCheck>,
}

impl ActivityLog {
    pub fn record(&mut self, activity: &Activity) {
        self.since_ms.get_or_insert(activity.at_ms);
        let count = u64::from(activity.count);
        match activity.kind {
            ActivityKind::Download => self.downloads += count,
            ActivityKind::File => self.files += count,
            ActivityKind::Mail => self.mail += count,
            ActivityKind::Program => self.programs += count,
            ActivityKind::Startup => self.startup += count,
        }
        for sample in &activity.samples {
            if sample.threat {
                self.threats += 1;
            }
            self.recent.push_front(RecentCheck {
                at_ms: activity.at_ms,
                kind: activity.kind,
                name: sample.name.clone(),
                threat: sample.threat,
            });
        }
        self.recent.truncate(MAX_RECENT);
    }
}

/// Zobrazovaný název: jen jméno souboru, ne celá cesta.
pub fn display_name(path: &Path) -> String {
    path.file_name()
        .map_or_else(|| path.to_string_lossy(), |name| name.to_string_lossy())
        .chars()
        .filter(|c| !c.is_control())
        .take(120)
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn finding(path: &str, sha: &str) -> Finding {
        serde_json::from_value(serde_json::json!({
            "path": path, "sha256": sha, "ruleId": "r", "ruleName": "MAL_Test",
            "ruleVersion": 1, "ruleDescription": "", "severity": "high", "testOnly": false,
            "evidence": [], "identity": { "device": 0, "inode": 0, "size": 0, "modifiedSec": 0,
                "modifiedNsec": 0, "changedSec": 0, "changedNsec": 0 },
            "changedDuringRead": false, "archiveEntry": null, "origin": null
        }))
        .unwrap()
    }

    fn story(path: &str, outcome: StoryOutcome) -> Story {
        Story {
            id: path.into(),
            detected_at_ms: 1,
            source: StorySource::Realtime,
            finding: finding(path, "aa"),
            provenance: Provenance::default(),
            chain: Vec::new(),
            outcome,
            updated_at_ms: 1,
        }
    }

    #[test]
    fn stories_survive_a_restart_without_duplicates() {
        let tmp = tempfile::tempdir().unwrap();
        let mut book = StoryBook::load(tmp.path());
        book.add(story("/x/a.app", StoryOutcome::Reported), tmp.path());
        book.add(story("/x/a.app", StoryOutcome::Reported), tmp.path());
        book.add(story("/x/b.app", StoryOutcome::Reported), tmp.path());
        let reloaded = StoryBook::load(tmp.path());
        assert_eq!(reloaded.list().len(), 2);
        assert_eq!(reloaded.list()[0].finding.path, "/x/b.app", "newest first");
    }

    #[test]
    fn cleaning_later_updates_the_story_and_resolved_ones_are_not_rechecked() {
        let tmp = tempfile::tempdir().unwrap();
        let mut book = StoryBook::default();
        book.add(story("/x/a.app", StoryOutcome::Reported), tmp.path());
        let paths = vec!["/x/a.app".to_string()];
        assert_eq!(book.unresolved_paths(&paths), paths);
        let done = StoryOutcome::Quarantined {
            item_id: "q1".into(),
            process_terminated: false,
        };
        book.record_outcome("/x/a.app", done.clone(), 2, tmp.path());
        assert_eq!(book.list()[0].outcome, done);
        assert!(book.unresolved_paths(&paths).is_empty());
    }

    #[test]
    fn a_damaged_story_file_is_ignored() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join(STORIES_FILE), b"[{").unwrap();
        assert!(StoryBook::load(tmp.path()).list().is_empty());
    }

    #[test]
    fn activity_is_counted_by_kind_and_recent_items_are_bounded() {
        let mut log = ActivityLog::default();
        for i in 0..40 {
            log.record(&Activity {
                at_ms: i,
                kind: ActivityKind::Download,
                count: 3,
                samples: vec![ActivitySample {
                    name: format!("f{i}"),
                    threat: i == 39,
                }],
            });
        }
        assert_eq!(log.downloads, 120);
        assert_eq!(log.threats, 1);
        assert_eq!(log.recent.len(), MAX_RECENT);
        assert_eq!(log.recent[0].name, "f39");
        assert_eq!(log.since_ms, Some(0));
    }

    #[test]
    fn files_are_sorted_into_radar_bands_by_location() {
        assert_eq!(
            ActivityKind::for_path(Path::new("/Users/eva/Downloads/a.zip")),
            ActivityKind::Download
        );
        assert_eq!(
            ActivityKind::for_path(Path::new(
                "/Users/eva/Library/Mail/V10/x/Attachments/1/a.pdf"
            )),
            ActivityKind::Mail
        );
        assert_eq!(
            ActivityKind::for_path(Path::new("/Users/eva/Library/LaunchAgents/com.x.plist")),
            ActivityKind::Startup
        );
        assert_eq!(
            ActivityKind::for_path(Path::new("/Users/eva/Desktop/a.txt")),
            ActivityKind::File
        );
        assert_eq!(display_name(Path::new("/a/b\u{7}c.txt")), "bc.txt");
    }
}
