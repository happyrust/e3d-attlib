//! EXMAP — `(DB_Attribute::type, size, ityp, isUDA) → DBE_Base::expType`
//! dispatch table, reproduced from IDA `sub_51D368F` (MTR trace name
//! `exprlib/EXMAP`).
//!
//! See `docs/ida-3.1-attributes.md` §3 for the full table and
//! `ida_exports/3.1/attribute_types.json` for the machine-readable copy.
//!
//! The `expType` codomain is named in [`ExpType`] using the symbolic
//! names recovered from `DBE_Base::typeAsString` (`0x59b6d40`) and
//! `DBE_Base::toVarType` (`0x59b6c50`).

/// Named values of the `DBE_Base::expType` enum.
///
/// Values are kept as their raw integer (the integer is what the dispatch
/// emits). `Unknown(N)` covers the not-officially-named codomain entries
/// (16 and 18) plus any value outside the observed set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpType {
    /// 1 — scalar boolean.
    Boolean,
    /// 2 — scalar real / int (shared f64 storage). The IDA `typeAsString`
    /// label is "real/int"; e3d-io's decoder distinguishes Integer from
    /// RealScalar based on the source `DB_Attribute::type` (`type=1` →
    /// integer 1-word storage, `type=2` → f64 2-word storage). This
    /// variant is the IDA-literal carrier.
    Real,
    /// e3d-attlib-internal variant: `type=1, size=1` — Integer scalar,
    /// 1 word `i32`. Not in the IDA EXMAP codomain; emitted by our
    /// dispatcher so decoders know to use `i32` reads.
    Integer,
    /// e3d-attlib-internal variant: `type=2, size=1` — Real scalar,
    /// 2 words `f64` (Fortran word-swap). Same caveat as `Integer`.
    RealScalar,
    /// 3 — scalar text.
    Text,
    /// 4 — scalar `DBREF`.
    DbRef,
    /// 6 — POSITION (3 doubles).
    Position,
    /// 7 — DIRECTION (3 doubles).
    Direction,
    /// 8 — ORIENTATION (9 doubles).
    Orientation,
    /// 10 — REAL_ARRAY.
    RealArray,
    /// 11 — BOOLEAN_ARRAY (inferred via `DBE_Base::equivalentScalarType`).
    BooleanArray,
    /// 12 — DBREF_ARRAY.
    DbRefArray,
    /// 13 — INT_ARRAY (paired with REAL scalar in `equivalentScalarType`).
    IntArray,
    /// 17 — TEXT_ARRAY.
    TextArray,
    /// 19 — BLOB.
    Blob,
    /// Any value not in the named set (most commonly 16 from
    /// `DB_Attribute::type==10` or 18 self-pair sentinel).
    Unknown(u32),
}

impl ExpType {
    pub fn raw(self) -> u32 {
        use ExpType::*;
        match self {
            Boolean => 1,
            // Both Integer and RealScalar collapse to IDA's "Real" (=2)
            // because IDA stores them in the same expType carrier.
            Real | Integer | RealScalar => 2,
            Text => 3,
            DbRef => 4,
            Position => 6,
            Direction => 7,
            Orientation => 8,
            RealArray => 10,
            BooleanArray => 11,
            DbRefArray => 12,
            IntArray => 13,
            TextArray => 17,
            Blob => 19,
            Unknown(v) => v,
        }
    }

    pub fn from_raw(v: u32) -> ExpType {
        use ExpType::*;
        match v {
            1 => Boolean,
            2 => Real,
            3 => Text,
            4 => DbRef,
            6 => Position,
            7 => Direction,
            8 => Orientation,
            10 => RealArray,
            11 => BooleanArray,
            12 => DbRefArray,
            13 => IntArray,
            17 => TextArray,
            19 => Blob,
            other => Unknown(other),
        }
    }

    /// Total word count for one scalar / one element of the type.
    ///
    /// Used by the byte decoder to know how many consecutive words to
    /// consume from an element record's slot area. For array forms the
    /// caller should multiply by the array length read from the slot's
    /// count word.
    pub fn word_count_per_element(self) -> Option<usize> {
        use ExpType::*;
        let n = match self {
            Boolean | Integer | Text | DbRef | Blob | Unknown(_) => 1,
            // f64-backed scalars take 2 words (Fortran word-swap).
            Real | RealScalar => 2,
            // Position/Direction = 3 doubles = 6 words.
            Position | Direction => 6,
            // Orientation = 9 doubles = 18 words.
            Orientation => 18,
            // Array variants are variable-length and need a count word
            // at the head of the slot.
            RealArray | BooleanArray | DbRefArray | IntArray | TextArray => 0,
        };
        Some(n)
    }
}

/// Dispatch `(type, size, ityp, isUDA) → expType` as in IDA `sub_51D368F`.
///
/// `type` is `DB_Attribute::type` (1..12 in practice), `size` is the
/// attribute's element count (1 = scalar, !=1 = array), `ityp` is
/// `DB_Attribute::ityp` (special values {23,29,38,48} force `Text`),
/// and `is_uda` is the `hash > 0x171FAD39` UDA flag.
///
/// Returns `None` when the input pattern is outside the table (the IDA
/// reference would raise an `MR_Message` error in that case).
pub fn exmap_dispatch(ty: u32, size: u32, ityp: u32, is_uda: bool) -> Option<ExpType> {
    // The `type==2` branch + the `ityp` override take precedence over
    // the per-type switch (faithful to IDA control flow). Note: for
    // type==2 size==1 we emit `RealScalar` instead of the literal
    // `Real` so decoders pick the 2-word f64 reader.
    if ty == 2 {
        return Some(if size == 1 {
            ExpType::RealScalar
        } else {
            ExpType::RealArray
        });
    }
    if matches!(ityp, 23 | 29 | 38 | 48) {
        return Some(ExpType::Text);
    }
    // For type==1 size==1 we also distinguish: emit `Integer` (1-word
    // i32) instead of the IDA-literal `Real`.
    if ty == 1 {
        return Some(if size == 1 {
            ExpType::Integer
        } else {
            ExpType::IntArray
        });
    }
    let raw = match ty {
        3 => {
            if size == 1 {
                1
            } else {
                11
            }
        }
        4 => 3,
        5 => {
            if size == 1 {
                4
            } else {
                12
            }
        }
        6 => {
            if size == 1 || is_uda {
                3
            } else {
                17
            }
        }
        7 => 7,
        8 => {
            // type==8 scalar -> Real (per IDA); we emit RealScalar.
            if size == 1 {
                return Some(ExpType::RealScalar);
            }
            6
        }
        9 => 8,
        10 => 16,
        11 => {
            if size == 1 {
                3
            } else {
                17
            }
        }
        12 => 19,
        _ => return None,
    };
    Some(ExpType::from_raw(raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_known_combinations() {
        // type==2 size==1 -> RealScalar (e3d-attlib refinement; IDA: Real)
        assert_eq!(exmap_dispatch(2, 1, 0, false), Some(ExpType::RealScalar));
        // type==2 size==3 -> RealArray
        assert_eq!(exmap_dispatch(2, 3, 0, false), Some(ExpType::RealArray));
        // type==1 size==1 -> Integer (e3d-attlib refinement; IDA: Real)
        assert_eq!(exmap_dispatch(1, 1, 0, false), Some(ExpType::Integer));
        // type==1 size==4 -> IntArray
        assert_eq!(exmap_dispatch(1, 4, 0, false), Some(ExpType::IntArray));
        // type==3 size==1 -> Boolean
        assert_eq!(exmap_dispatch(3, 1, 0, false), Some(ExpType::Boolean));
        // type==3 size==2 -> BooleanArray
        assert_eq!(exmap_dispatch(3, 2, 0, false), Some(ExpType::BooleanArray));
        // type==4 -> Text
        assert_eq!(exmap_dispatch(4, 1, 0, false), Some(ExpType::Text));
        // type==5 size==1 -> DbRef
        assert_eq!(exmap_dispatch(5, 1, 0, false), Some(ExpType::DbRef));
        // type==7 -> Direction
        assert_eq!(exmap_dispatch(7, 1, 0, false), Some(ExpType::Direction));
        // type==9 -> Orientation
        assert_eq!(exmap_dispatch(9, 1, 0, false), Some(ExpType::Orientation));
        // type==12 -> Blob
        assert_eq!(exmap_dispatch(12, 1, 0, false), Some(ExpType::Blob));
        // type==8 size==1 -> RealScalar (e3d-attlib refinement)
        assert_eq!(exmap_dispatch(8, 1, 0, false), Some(ExpType::RealScalar));
        // type==8 size==3 -> Position
        assert_eq!(exmap_dispatch(8, 3, 0, false), Some(ExpType::Position));
    }

    #[test]
    fn ityp_override_routes_to_text() {
        // Any type with ityp in {23,29,38,48} -> Text (after the type==2 check)
        for ityp in [23u32, 29, 38, 48] {
            assert_eq!(exmap_dispatch(7, 1, ityp, false), Some(ExpType::Text));
            assert_eq!(exmap_dispatch(11, 5, ityp, false), Some(ExpType::Text));
        }
        // type==2 takes precedence and is NOT overridden by ityp.
        // e3d-attlib emits RealScalar for type=2 size=1 (refinement of IDA Real).
        assert_eq!(exmap_dispatch(2, 1, 23, false), Some(ExpType::RealScalar));
    }

    #[test]
    fn uda_routes_type6_to_text_scalar() {
        // For type==6 with size>1, isUDA=true forces Text (scalar) instead
        // of TextArray.
        assert_eq!(exmap_dispatch(6, 5, 0, true), Some(ExpType::Text));
        assert_eq!(exmap_dispatch(6, 5, 0, false), Some(ExpType::TextArray));
    }

    #[test]
    fn unsupported_type_returns_none() {
        assert_eq!(exmap_dispatch(0, 1, 0, false), None);
        assert_eq!(exmap_dispatch(99, 1, 0, false), None);
    }
}
