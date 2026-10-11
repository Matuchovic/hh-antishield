//! Porovnání obsahu souboru s pravidly v jednom průchodu po blocích.
//!
//! Každý blok jde zároveň do SHA-256 a do hledání bajtových vzorů. Vzory, které
//! přesahují hranici bloků, se hledají v malém okně „konec předchozích dat +
//! začátek nového bloku“, takže výsledek nezávisí na velikosti bloků
//! (hlídá to property test).

use aho_corasick::AhoCorasick;
use sha2::{Digest, Sha256};

use crate::rules::RulePack;
use crate::types::Evidence;

/// Kolik prvních bajtů si držíme (EICAR a signatury formátů).
pub const HEAD_LEN: usize = 128;
/// Kolik posledních bajtů si držíme (blok `koly` u DMG).
pub const TAIL_LEN: usize = 512;

/// SHA-256 oficiálního 68bajtového testovacího souboru EICAR.
pub const EICAR_SHA256: [u8; 32] = [
    0x27, 0x5a, 0x02, 0x1b, 0xbf, 0xb6, 0x48, 0x9e, 0x54, 0xd4, 0x71, 0x89, 0x9f, 0x7d, 0xb9, 0xd1,
    0x66, 0x3f, 0xc6, 0x95, 0xec, 0x2f, 0xe2, 0xa2, 0xc4, 0x53, 0x8a, 0xab, 0xf6, 0x51, 0xfd, 0x0f,
];
const EICAR_LEN: usize = 68;
const EICAR_MAX_FILE_LEN: u64 = 128;

/// Archiv nebo kontejner, který v0.1 nerozbaluje.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveFormat {
    Zip,
    Gzip,
    Bzip2,
    Xz,
    SevenZip,
    Rar,
    Xar,
    Dmg,
}

/// Shoda jednoho pravidla.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleMatch {
    pub rule_index: usize,
    pub evidence: Evidence,
}

/// Výsledek porovnání celého obsahu.
#[derive(Debug, Clone)]
pub struct Verdict {
    pub sha256: [u8; 32],
    pub size: u64,
    pub matches: Vec<RuleMatch>,
    pub archive: Option<ArchiveFormat>,
}

/// Postupné porovnání obsahu jednoho souboru.
pub struct ContentMatcher<'a> {
    rules: &'a RulePack,
    hasher: Sha256,
    size: u64,
    head: Vec<u8>,
    tail: Vec<u8>,
    overlap: Vec<u8>,
    first_hit: Vec<Option<u64>>,
}

impl std::fmt::Debug for ContentMatcher<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContentMatcher")
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

impl<'a> ContentMatcher<'a> {
    pub fn new(rules: &'a RulePack) -> Self {
        Self {
            rules,
            hasher: Sha256::new(),
            size: 0,
            head: Vec::with_capacity(HEAD_LEN),
            tail: Vec::with_capacity(TAIL_LEN),
            overlap: Vec::new(),
            first_hit: vec![None; rules.pattern_count()],
        }
    }

    /// Počet dosud přijatých bajtů.
    pub fn bytes_seen(&self) -> u64 {
        self.size
    }

    pub fn feed(&mut self, chunk: &[u8]) {
        if chunk.is_empty() {
            return;
        }
        self.hasher.update(chunk);
        if self.head.len() < HEAD_LEN {
            let take = (HEAD_LEN - self.head.len()).min(chunk.len());
            self.head.extend_from_slice(&chunk[..take]);
        }
        keep_last(&mut self.tail, chunk, TAIL_LEN);
        let rules = self.rules;
        if let Some(automaton) = rules.patterns() {
            self.search(automaton, chunk);
        }
        self.size += chunk.len() as u64;
    }

    fn search(&mut self, automaton: &AhoCorasick, chunk: &[u8]) {
        let keep = self.rules.max_pattern_len().saturating_sub(1);
        if !self.overlap.is_empty() {
            // Vzory, které začínají v předchozích datech a končí v tomto bloku.
            let prefix = keep.min(chunk.len());
            let mut window = Vec::with_capacity(self.overlap.len() + prefix);
            window.extend_from_slice(&self.overlap);
            window.extend_from_slice(&chunk[..prefix]);
            let split = self.overlap.len();
            let base = self.size - split as u64;
            let hits: Vec<(usize, u64)> = automaton
                .find_overlapping_iter(&window)
                .filter(|m| m.start() < split && m.end() > split)
                .map(|m| (m.pattern().as_usize(), base + m.start() as u64))
                .collect();
            for (pattern, offset) in hits {
                self.record(pattern, offset);
            }
        }
        let base = self.size;
        let hits: Vec<(usize, u64)> = automaton
            .find_overlapping_iter(chunk)
            .map(|m| (m.pattern().as_usize(), base + m.start() as u64))
            .collect();
        for (pattern, offset) in hits {
            self.record(pattern, offset);
        }
        if keep > 0 {
            keep_last(&mut self.overlap, chunk, keep);
        }
    }

    fn record(&mut self, pattern: usize, offset: u64) {
        let slot = &mut self.first_hit[pattern];
        if slot.is_none_or(|existing| offset < existing) {
            *slot = Some(offset);
        }
    }

    pub fn finish(self) -> Verdict {
        let digest = self.hasher.finalize();
        let mut sha256 = [0u8; 32];
        sha256.copy_from_slice(&digest);

        let mut matches = Vec::new();
        if let Some(rule_index) = self.rules.hash_rule(&sha256) {
            matches.push(RuleMatch {
                rule_index,
                evidence: Evidence::Sha256Match {
                    digest_hex: hex::encode(sha256),
                },
            });
        }
        for (pattern, hit) in self.first_hit.iter().enumerate() {
            if let Some(offset) = hit {
                matches.push(RuleMatch {
                    rule_index: self.rules.pattern_rule(pattern),
                    evidence: Evidence::BytePattern {
                        offset: *offset,
                        length: u32::try_from(self.rules.pattern(pattern).len())
                            .unwrap_or(u32::MAX),
                    },
                });
            }
        }
        if let Some(rule_index) = self.rules.eicar_rule()
            && is_eicar_file(&self.head, self.size)
        {
            matches.push(RuleMatch {
                rule_index,
                evidence: Evidence::EicarStandard,
            });
        }
        let archive = detect_archive(&self.head, &self.tail, self.size);
        Verdict {
            sha256,
            size: self.size,
            matches,
            archive,
        }
    }
}

/// Ponechá ve `buffer` posledních `max` bajtů z `buffer + chunk`.
fn keep_last(buffer: &mut Vec<u8>, chunk: &[u8], max: usize) {
    if chunk.len() >= max {
        buffer.clear();
        buffer.extend_from_slice(&chunk[chunk.len() - max..]);
    } else {
        buffer.extend_from_slice(chunk);
        if buffer.len() > max {
            let excess = buffer.len() - max;
            buffer.drain(..excess);
        }
    }
}

/// Oficiální definice EICAR: 68 znaků na začátku souboru, za nimi jen mezera,
/// tabulátor, LF, CR nebo Ctrl-Z, celkem nejvýš 128 bajtů. Řetězec samotný
/// v binárce není, porovnává se jeho SHA-256.
pub fn is_eicar_file(head: &[u8], size: u64) -> bool {
    if !(EICAR_LEN as u64..=EICAR_MAX_FILE_LEN).contains(&size) || head.len() as u64 != size {
        return false;
    }
    let digest = Sha256::digest(&head[..EICAR_LEN]);
    digest.as_slice() == EICAR_SHA256
        && head[EICAR_LEN..]
            .iter()
            .all(|b| matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x1a))
}

/// Rozpozná archiv podle signatury. Obsah archivu v0.1 nekontroluje.
pub fn detect_archive(head: &[u8], tail: &[u8], size: u64) -> Option<ArchiveFormat> {
    let starts = |magic: &[u8]| head.starts_with(magic);
    if starts(b"PK\x03\x04") || starts(b"PK\x05\x06") || starts(b"PK\x07\x08") {
        Some(ArchiveFormat::Zip)
    } else if starts(&[0x1f, 0x8b]) {
        Some(ArchiveFormat::Gzip)
    } else if starts(b"BZh") {
        Some(ArchiveFormat::Bzip2)
    } else if starts(&[0xfd, b'7', b'z', b'X', b'Z', 0x00]) {
        Some(ArchiveFormat::Xz)
    } else if starts(&[b'7', b'z', 0xbc, 0xaf, 0x27, 0x1c]) {
        Some(ArchiveFormat::SevenZip)
    } else if starts(b"Rar!\x1a\x07") {
        Some(ArchiveFormat::Rar)
    } else if starts(b"xar!") {
        Some(ArchiveFormat::Xar)
    } else if size >= TAIL_LEN as u64 && tail.len() == TAIL_LEN && tail.starts_with(b"koly") {
        Some(ArchiveFormat::Dmg)
    } else {
        None
    }
}

/// Porovná buffer v paměti po blocích dané velikosti (self-test a testy).
pub fn scan_buffer(rules: &RulePack, data: &[u8], chunk_size: usize) -> Verdict {
    let mut matcher = ContentMatcher::new(rules);
    for chunk in data.chunks(chunk_size.max(1)) {
        matcher.feed(chunk);
    }
    matcher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keep_last_works() {
        let mut b = Vec::new();
        keep_last(&mut b, b"abc", 4);
        assert_eq!(b, b"abc");
        keep_last(&mut b, b"de", 4);
        assert_eq!(b, b"bcde");
        keep_last(&mut b, b"123456", 4);
        assert_eq!(b, b"3456");
    }

    #[test]
    fn archive_signatures() {
        assert_eq!(
            detect_archive(b"PK\x03\x04rest", b"", 10),
            Some(ArchiveFormat::Zip)
        );
        assert_eq!(
            detect_archive(&[0x1f, 0x8b, 8], b"", 3),
            Some(ArchiveFormat::Gzip)
        );
        assert_eq!(
            detect_archive(b"xar!....", b"", 8),
            Some(ArchiveFormat::Xar)
        );
        let mut tail = b"koly".to_vec();
        tail.resize(TAIL_LEN, 0);
        assert_eq!(
            detect_archive(b"\0\0\0\0", &tail, 4096),
            Some(ArchiveFormat::Dmg)
        );
        assert_eq!(detect_archive(b"hello", b"hello", 5), None);
    }

    #[test]
    fn eicar_definition() {
        let eicar = crate::testvectors::eicar();
        assert!(is_eicar_file(&eicar, 68));
        let mut padded = eicar.clone();
        padded.extend_from_slice(b" \t\r\n\x1a");
        assert!(is_eicar_file(&padded, padded.len() as u64));
        let mut too_long = eicar.clone();
        too_long.resize(129, b' ');
        assert!(!is_eicar_file(&too_long[..128], 129));
        let mut tail_text = eicar.clone();
        tail_text.extend_from_slice(b" x");
        assert!(!is_eicar_file(&tail_text, tail_text.len() as u64));
        let mut shifted = vec![b' '];
        shifted.extend_from_slice(&eicar);
        assert!(!is_eicar_file(&shifted, shifted.len() as u64));
        assert!(!is_eicar_file(&eicar[..67], 67));
    }
}
