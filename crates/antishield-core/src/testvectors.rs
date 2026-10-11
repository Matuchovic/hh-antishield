//! Neškodné testovací vzorky pro self-test a testy.
//!
//! Testovací řetězec EICAR v binárce není uložený vcelku: je zakódovaný XORem,
//! aby jiné antiviry neoznačily samotný engine. Syntetické vzorky vznikají
//! hashováním, takže jejich obsah v binárce také není.

use sha2::{Digest, Sha256};

const EICAR_XOR_KEY: u8 = 0x5a;
const EICAR_ENCODED: [u8; 68] = [
    0x02, 0x6f, 0x15, 0x7b, 0x0a, 0x7f, 0x1a, 0x1b, 0x0a, 0x01, 0x6e, 0x06, 0x0a, 0x00, 0x02, 0x6f,
    0x6e, 0x72, 0x0a, 0x04, 0x73, 0x6d, 0x19, 0x19, 0x73, 0x6d, 0x27, 0x7e, 0x1f, 0x13, 0x19, 0x1b,
    0x08, 0x77, 0x09, 0x0e, 0x1b, 0x14, 0x1e, 0x1b, 0x08, 0x1e, 0x77, 0x1b, 0x14, 0x0e, 0x13, 0x0c,
    0x13, 0x08, 0x0f, 0x09, 0x77, 0x0e, 0x1f, 0x09, 0x0e, 0x77, 0x1c, 0x13, 0x16, 0x1f, 0x7b, 0x7e,
    0x12, 0x71, 0x12, 0x70,
];

/// Standardní 68bajtový testovací soubor EICAR (jen v paměti).
pub fn eicar() -> Vec<u8> {
    EICAR_ENCODED.iter().map(|b| b ^ EICAR_XOR_KEY).collect()
}

/// Deterministický syntetický vzorek 4 096 bajtů. Jeho SHA-256 je ve
/// testovací sadě pravidel jako indikátor `HH-TEST-SYNTH-xxxx`.
pub fn synthetic_sample(number: u32) -> Vec<u8> {
    let label = format!("hh-antishield-synthetic-{number:04}");
    let mut out = Vec::with_capacity(4096);
    for block in 0u32..128 {
        let mut hasher = Sha256::new();
        hasher.update(label.as_bytes());
        hasher.update(block.to_le_bytes());
        out.extend_from_slice(&hasher.finalize());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eicar_vector_is_intact() {
        let data = eicar();
        assert_eq!(data.len(), 68);
        assert_eq!(
            Sha256::digest(&data).as_slice(),
            crate::matcher::EICAR_SHA256.as_slice()
        );
    }

    #[test]
    fn synthetic_samples_are_stable() {
        assert_eq!(
            hex::encode(Sha256::digest(synthetic_sample(1))),
            "9165bb977ff9815b22c7b87a7721697a88d6669a69c4b4b40689f3774632c64a"
        );
        assert_eq!(
            hex::encode(Sha256::digest(synthetic_sample(2))),
            "31c21cfd84d11f0ca11d09f73f7e2a400f0f71f0df44c074044cbb347d1b2c29"
        );
    }
}
