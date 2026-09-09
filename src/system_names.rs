//! System attribute hash → name lookup, extracted from E3D 3.1 `core.dll`.
//!
//! The table contains 6377 entries pulled from `?ATT_<NAME>@@3...` global
//! symbols (see `ida_exports/3.1/attribute_names.json` and goal
//! `e3d31-attribute-parsing` Slice 3 for the IDA evidence trail).
//!
//! The table is sorted by hash, so lookups are O(log n) binary searches.
//!
//! For hashes outside the system range (i.e. `hash > 0x171FAD39`), names are
//! UDAs and must be resolved from the external attribute data file at
//! runtime (see Slice 5/6 of the parent goal). For system hashes that miss
//! the table, the caller can fall back to [`crate::hash::db1_dehash`].

mod system_names_table {
    include!("system_names_table.rs");
}

use system_names_table::SYSTEM_NAME_TABLE;

/// Inclusive lower bound of the system attribute hash range (== `0x81BF2`).
pub const SYSTEM_HASH_MIN: u32 = 0x0008_1BF2;

/// Inclusive upper bound of the system attribute hash range (== `0x171FAD39`).
///
/// `DB_Attribute::isUDA()` is implemented as `hash > 0x171FAD39` — anything
/// strictly greater than this is a user-defined attribute.
pub const SYSTEM_HASH_MAX: u32 = 0x171F_AD39;

/// Total number of system attributes in the bundled table.
pub fn entry_count() -> usize {
    SYSTEM_NAME_TABLE.len()
}

/// Look up a system attribute name by its hash.
///
/// Returns `None` if the hash is not a known system attribute. Caller should
/// fall back to [`crate::hash::db1_dehash`] for unknown hashes that still
/// fall within the base-27 dehash range, and treat anything beyond
/// `SYSTEM_HASH_MAX` as a UDA.
pub fn lookup_by_hash(hash: u32) -> Option<&'static str> {
    SYSTEM_NAME_TABLE
        .binary_search_by_key(&hash, |&(h, _)| h)
        .ok()
        .map(|idx| SYSTEM_NAME_TABLE[idx].1)
}

/// Returns true when the hash falls inside the documented system attribute
/// range (i.e. base-27 dehash applies; not a UDA).
pub fn is_system_hash(hash: u32) -> bool {
    (SYSTEM_HASH_MIN..=SYSTEM_HASH_MAX).contains(&hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::db1_hash;

    #[test]
    fn table_is_sorted_and_unique() {
        let mut prev: Option<u32> = None;
        for (h, _) in SYSTEM_NAME_TABLE {
            if let Some(p) = prev {
                assert!(*h > p, "table not strictly sorted at hash {h:#x}");
            }
            prev = Some(*h);
        }
    }

    #[test]
    fn known_system_attributes_resolve() {
        // Sample names verified against IDA — see slice_3_complete in
        // goals/e3d31-attribute-parsing/progress.jsonl.
        for name in [
            "PTYP", "BORE", "HBOR", "DESP", "POSI", "ORIE", "TYPE", "RPRO", "CDPR", "LDPR", "TDPR",
            "PROPRE", "REALEV", "NAME", "OBST",
        ] {
            let h = db1_hash(name);
            let got = lookup_by_hash(h);
            assert_eq!(got, Some(name), "lookup failed for {name} (hash {h:#x})");
        }
    }

    #[test]
    fn unknown_hash_returns_none() {
        // Pick a hash that cannot exist (well above max).
        assert_eq!(lookup_by_hash(0xFFFF_FFFF), None);
        // And a few that fall in dehash range but are unlikely to be system
        // names: hash for "OWNE" and "USER" both verified absent during
        // Slice 3 extraction.
        assert_eq!(lookup_by_hash(db1_hash("OWNE")), None);
        assert_eq!(lookup_by_hash(db1_hash("USER")), None);
    }

    #[test]
    fn is_system_hash_boundaries() {
        assert!(!is_system_hash(SYSTEM_HASH_MIN - 1));
        assert!(is_system_hash(SYSTEM_HASH_MIN));
        assert!(is_system_hash(SYSTEM_HASH_MAX));
        assert!(!is_system_hash(SYSTEM_HASH_MAX + 1));
    }

    #[test]
    fn entry_count_matches_extraction() {
        assert_eq!(entry_count(), 6377);
    }
}
