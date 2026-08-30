//! Angle-attribute hash set, extracted from the E3D 3.1 exported catalog.
//!
//! An attribute is an "angle" when its catalog `UNIT` field is
//! `db1_hash("ANGL")` (== 773119). 125 of the 4271 exported attributes carry
//! it — `BANG`, `ASUB`, `ADEG`, the shear angles `Pxbshear`/`Xbshear`, and so
//! on.
//!
//! Why this matters to the decoder: an angle stored in a single record word
//! holds hundredths of a degree. `SCTN.Bangle` writes `4294958296` (−9000 as
//! `i32`) where `q att` prints `−90`, and `SSLC.Pxbshear` writes `1150` where
//! it prints `11.5`. Without the unit the descriptor layer can only surface
//! the word as an unsigned [`crate`] `Word`, which reads `4294958296` — a
//! number the generation chain would then feed into geometry as-is. attlib
//! holds no `ATGTDF` definition for several of these (`BANG` among them), so
//! the type cannot come from there; the catalog is the authority.
//!
//! The table is sorted by hash, so membership is an O(log n) binary search.

mod angle_attrs_table {
    include!("angle_attrs_table.rs");
}

use angle_attrs_table::ANGLE_ATTR_HASHES;

/// Number of angle attributes in the bundled table.
pub fn angle_attr_count() -> usize {
    ANGLE_ATTR_HASHES.len()
}

/// Whether an attribute hash carries the catalog `ANGL` unit.
///
/// A one-word value of such an attribute is centidegrees: divide by 100 to get
/// the degrees E3D prints. A multi-word (real) angle needs no scaling — it is
/// already stored as the degree value.
pub fn is_angle_attr(hash: u32) -> bool {
    ANGLE_ATTR_HASHES.binary_search(&hash).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::db1_hash;

    #[test]
    fn table_is_sorted_and_unique() {
        let mut prev: Option<u32> = None;
        for &hash in ANGLE_ATTR_HASHES {
            if let Some(p) = prev {
                assert!(hash > p, "table not strictly sorted at hash {hash:#x}");
            }
            prev = Some(hash);
        }
    }

    #[test]
    fn bang_is_an_angle() {
        // `BANG` (elbow angle) is the attribute that motivated this table:
        // attlib has no definition for it, so only the catalog unit tells the
        // decoder it is an angle. 679457 == db1_hash("BANG").
        assert_eq!(db1_hash("BANG"), 679457);
        assert!(is_angle_attr(679457));
        assert!(is_angle_attr(db1_hash("BANG")));
    }

    #[test]
    fn known_angles_resolve() {
        for name in ["BANG", "ASUB", "ADEG", "OANG", "PANG"] {
            assert!(is_angle_attr(db1_hash(name)), "{name} should be an angle");
        }
    }

    #[test]
    fn non_angles_are_absent() {
        // Lengths and bores are not angles.
        for name in ["XLEN", "YLEN", "ZLEN", "DIAM", "BORE"] {
            assert!(!is_angle_attr(db1_hash(name)), "{name} is not an angle");
        }
    }

    #[test]
    fn count_matches_export() {
        assert_eq!(angle_attr_count(), 125);
    }
}
