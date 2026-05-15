/// PDMS/E3D base-27 name hash.
/// Each uppercase letter maps to 1-26, accumulated as val = val*27 + char_val, offset by 0x81BF1.
pub fn db1_hash(name: &str) -> u32 {
    let mut val: u32 = 0;
    for c in name.to_uppercase().chars().rev() {
        if c.is_ascii_uppercase() {
            val = val.wrapping_mul(27).wrapping_add((c as u32) - 64);
        }
    }
    val.wrapping_add(0x81BF1)
}

/// Reverse hash: decode a hash value back to a PDMS name.
pub fn db1_dehash(hash: u32) -> Option<String> {
    const BASE27_MIN: u32 = 0x81BF2;
    const BASE27_MAX: u32 = 0x171FAD39;

    if hash < BASE27_MIN || hash > BASE27_MAX {
        return None;
    }

    let mut k = hash - 0x81BF1;
    let mut result = String::new();

    while k > 0 {
        let c = ((k % 27) + 64) as u8 as char;
        result.push(c);
        k /= 27;
    }

    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_roundtrip() {
        for name in ["BORE", "HBOR", "DESP", "POSI", "ORIE", "TYPE", "OWNE"] {
            let h = db1_hash(name);
            let back = db1_dehash(h).unwrap();
            assert_eq!(name, &back, "roundtrip failed for {}", name);
        }
    }

    #[test]
    fn known_hashes() {
        assert_eq!(db1_hash("USER"), 0xD943A);
    }
}
