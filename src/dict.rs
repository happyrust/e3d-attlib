//! Offline decoder for per-attribute *dictionary meta-fields* in `attlib.dat`
//! — DCHC, PLCF, WNOEVT, WNOCLM and the other 63 columns of the E3D "ATTR of
//! ATTR" schema — without a live E3D session.
//!
//! # What this reproduces
//!
//! In `core.dll` every meta-field of an attribute is fetched through one
//! reader, `sub_55BB6C3` (PDMS *ATNLOG* / "AXALOG"), keyed by
//! `(attribute-hash, field-hash)`. `DB_Attribute::ReadData` (`0x58CE1F0`)
//! calls it once per field to fill the in-memory `DB_Attribute`; e.g.
//! `DB_Attribute::wnoevt` (`0x58D5290`) just returns the byte at `+184` that
//! `ReadData` loaded from field `WNOEVT` (`299311034`).
//!
//! The reader's tables are exactly the `attlib.dat` sections this crate
//! already parses (proven by tracing the ATTOPE loader `sub_55F4290`):
//!
//! * **ATGTDF** (directory slot 0) is the ordered 63-entry meta-field list
//!   (`dword_6BE26E0` + count `dword_6C08EB4`). A field's 1-based position
//!   here is its *ordinal*.
//! * **ATGTIX** (directory slot 2) is the *system attribute* index: sorted
//!   `(hash, packed)` pairs where `packed = page * 512 + word_offset`
//!   (`dword_6BD26E0` / `dword_6BDA6E0`).
//!
//! Each attribute's record is one `FHDBRN` block: a header of N per-field
//! offsets followed by the values. `FHDBRN` block numbers are 1-based, so a
//! record on ATGTIX page `p`, base `b` starts at file word
//! `row = (p - 1) * 512 + b - 2` (0-based, big-endian). For field ordinal `o`:
//!
//! ```text
//! off   = word[row + o]            // header slot
//!         == 0xFFFFFFFF (-1)  =>  use the field's ATGTDF schema default
//!         == 0               =>  inherited: follow the SYNO link to a parent
//!         else               =>  value = word[row + off]
//! ```
//!
//! For the integer reader the raw word is returned; for the boolean reader
//! (`WNOEVT`/`WNOCLM`) the runtime returns `word == 1` (the `-1/0` that
//! `sub_55BB6C3` case 1 produces, `& 1`).
//!
//! Attribute hashes `> SYSTEM_HASH_MAX` (UDAs) never carry a stored value
//! through this path; the reader hands back the schema default. The
//! [`AttrDict`] index is the **system** attribute namespace (ATGTIX slot 2)
//! only — the parallel *element-type / noun* dictionary (slot 6: `SBOX`,
//! `TUBE`, `LINE`, …) is a different namespace and is intentionally not
//! merged in here.
//!
//! # Validation
//!
//! Decoding DCHC (ordinal 49) reproduces the committed
//! `dchc_change_classes.json` for all 4270 named attributes, and PLCF
//! (ordinal 50) reproduces `plcf_flags.json` (58/58), against the E3D 3.1
//! dictionary. See `tests/dict_calibration.rs` for a portable subset check.

use std::collections::HashMap;
use std::path::Path;

use crate::hash::db1_dehash;
use crate::system_names::SYSTEM_HASH_MAX;

/// `DCHC` — change-class field hash (ordinal 49 in E3D 3.1).
pub const FIELD_DCHC: u32 = 596_407;
/// `PLCF` — "in tube" pipe-legality flag hash (ordinal 50).
pub const FIELD_PLCF: u32 = 652_066;
/// `WNOEVT` — want-no-event gate hash (ordinal 28). A put on a `WNOEVT`
/// attribute fires no change event at all — the gate before DCHC.
pub const FIELD_WNOEVT: u32 = 299_311_034;
/// `WNOCLM` — want-no-claim field hash (ordinal 29).
pub const FIELD_WNOCLM: u32 = 193_514_909;
/// `SYNO` — synonym link field hash (ordinal 56); followed to resolve an
/// inherited (`header == 0`) meta-field to its parent attribute.
pub const FIELD_SYNO: u32 = 837_586;

const WORDS_PER_PAGE: usize = 512;
const DELIMITER: u32 = 0xFFFF_FFFF;
/// ATGTDF/ATGTIX hash band: `[531442, 387951929]` is the base-27 PDMS range.
const HASH_MIN: u32 = 531_442;
const HASH_MAX: u32 = 387_951_929;

/// The raw disposition of one meta-field slot in an attribute's record,
/// before schema-default / synonym resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FieldSlot {
    /// A value is stored inline in the record at `word[row + off]`.
    Stored(u32),
    /// Header slot is `-1`: fall back to the field's ATGTDF default value.
    SchemaDefault,
    /// Header slot is `0`: the field is inherited from a parent (follow SYNO).
    Inherited,
}

/// A decoded value, tagging whether it came from the record or the schema
/// default pool. Both carry the same raw 32-bit word the runtime would read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolved {
    /// Value read from the attribute's own (or an inherited parent's) record.
    Stored(u32),
    /// Value taken from the field's ATGTDF schema default.
    Default(u32),
}

impl Resolved {
    /// The raw 32-bit word, regardless of source.
    pub fn word(self) -> u32 {
        match self {
            Resolved::Stored(w) | Resolved::Default(w) => w,
        }
    }
}

/// Offline reader for the `attlib.dat` attribute meta-dictionary.
///
/// Parse once with [`AttrDict::parse_file`], then query per attribute:
/// [`AttrDict::dchc`], [`AttrDict::wnoevt`], [`AttrDict::wnoclm`],
/// [`AttrDict::plcf`], or the generic [`AttrDict::resolve_int`] /
/// [`AttrDict::resolve_bool`]. Use [`AttrDict::attributes_with_flag`] to list
/// every attribute a boolean field is set on.
pub struct AttrDict {
    /// Whole file as big-endian 32-bit words.
    words: Vec<u32>,
    /// Meta-field hash -> 1-based ordinal (position in the system ATGTDF list).
    field_ordinal: HashMap<u32, usize>,
    /// Meta-field hash -> ATGTDF schema default word (kind-2 scalar fields).
    field_default: HashMap<u32, u32>,
    /// System attribute hash -> `(page, base)` record location from ATGTIX.
    index: HashMap<u32, (usize, usize)>,
    /// Ordinal of the SYNO field, if present (for inheritance resolution).
    syno_ordinal: Option<usize>,
}

impl AttrDict {
    /// Parse `attlib.dat` from disk.
    pub fn parse_file(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref();
        let bytes = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        Self::from_bytes(&bytes)
    }

    /// Parse `attlib.dat` from an in-memory image.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < WORDS_PER_PAGE * 2 * 4 {
            return Err(format!("attlib.dat too small: {} bytes", bytes.len()));
        }
        let n = bytes.len() / 4;
        let (chunks, _) = bytes[..n * 4].as_chunks::<4>();
        let words: Vec<u32> = chunks.iter().map(|&c| u32::from_be_bytes(c)).collect();

        // Directory page is 0-indexed page 1; its first 8 words are the
        // Fortran 1-indexed section start pages.
        let dir: Vec<u32> = (0..8).map(|k| words[WORDS_PER_PAGE + k]).collect();
        let (field_ordinal, field_default) = parse_atgtdf(&words, dir[0]);
        let index = parse_atgtix(&words, dir[2]);
        let syno_ordinal = field_ordinal.get(&FIELD_SYNO).copied();

        Ok(Self {
            words,
            field_ordinal,
            field_default,
            index,
            syno_ordinal,
        })
    }

    /// Number of system attributes in the ATGTIX index.
    pub fn attribute_count(&self) -> usize {
        self.index.len()
    }

    /// Number of meta-fields (columns) in the ATGTDF schema.
    pub fn field_count(&self) -> usize {
        self.field_ordinal.len()
    }

    /// 1-based ordinal of a meta-field (its column position), or `None` if the
    /// field hash is not in the schema.
    pub fn field_ordinal(&self, field_hash: u32) -> Option<usize> {
        self.field_ordinal.get(&field_hash).copied()
    }

    /// Iterator over every system attribute hash in the index.
    pub fn attribute_hashes(&self) -> impl Iterator<Item = u32> + '_ {
        self.index.keys().copied()
    }

    /// Raw disposition of `field_hash` on `attr_hash` (no default/synonym
    /// resolution). `None` if the attribute or field is absent.
    fn raw_slot(&self, attr_hash: u32, ordinal: usize) -> Option<FieldSlot> {
        let &(page, base) = self.index.get(&attr_hash)?;
        // row = (page - 1) * 512 + base - 2, computed signed to stay safe for
        // the smallest legal records before bounds-checking.
        let row = (page as i64 - 1) * WORDS_PER_PAGE as i64 + base as i64 - 2;
        let hi = row + ordinal as i64;
        if hi < 0 || hi as usize >= self.words.len() {
            return None;
        }
        let off = self.words[hi as usize];
        if off == DELIMITER {
            return Some(FieldSlot::SchemaDefault);
        }
        if off == 0 {
            return Some(FieldSlot::Inherited);
        }
        let vi = row + off as i64;
        if vi < 0 || vi as usize >= self.words.len() {
            return None;
        }
        Some(FieldSlot::Stored(self.words[vi as usize]))
    }

    /// Resolve a meta-field to its effective 32-bit word, following the same
    /// path as `sub_55BB6C3`: stored value, else schema default, else the SYNO
    /// inheritance chain. `None` when the field/attribute is unknown or an
    /// inherited value has no resolvable source.
    pub fn resolve(&self, attr_hash: u32, field_hash: u32) -> Option<Resolved> {
        let ordinal = *self.field_ordinal.get(&field_hash)?;
        // UDAs (hash beyond the system band) only ever get the schema default.
        if attr_hash > SYSTEM_HASH_MAX {
            return self
                .field_default
                .get(&field_hash)
                .map(|&w| Resolved::Default(w));
        }
        let mut cur = attr_hash;
        // Bounded to guard against a malformed synonym cycle.
        for _ in 0..64 {
            match self.raw_slot(cur, ordinal)? {
                FieldSlot::Stored(w) => return Some(Resolved::Stored(w)),
                FieldSlot::SchemaDefault => {
                    return self
                        .field_default
                        .get(&field_hash)
                        .map(|&w| Resolved::Default(w))
                }
                FieldSlot::Inherited => {
                    let syno = self.syno_ordinal?;
                    match self.raw_slot(cur, syno)? {
                        FieldSlot::Stored(parent) if parent != cur => cur = parent,
                        _ => return None,
                    }
                }
            }
        }
        None
    }

    /// Read a meta-field as a signed integer (the reader's raw-int path).
    pub fn resolve_int(&self, attr_hash: u32, field_hash: u32) -> Option<i64> {
        self.resolve(attr_hash, field_hash).map(|r| r.word() as i64)
    }

    /// Read a meta-field as a boolean. Matches the reader's case-1 conversion:
    /// the value is true iff the raw word is exactly `1`.
    pub fn resolve_bool(&self, attr_hash: u32, field_hash: u32) -> Option<bool> {
        self.resolve(attr_hash, field_hash).map(|r| r.word() == 1)
    }

    /// `DCHC` change class for an attribute (0 = no geometric consequence).
    pub fn dchc(&self, attr_hash: u32) -> Option<i64> {
        self.resolve_int(attr_hash, FIELD_DCHC)
    }

    /// `PLCF` — whether the attribute sets the pipe-legality "in tube" flag.
    pub fn plcf(&self, attr_hash: u32) -> bool {
        self.resolve_bool(attr_hash, FIELD_PLCF).unwrap_or(false)
    }

    /// `WNOEVT` — whether a put on this attribute fires no change event.
    pub fn wnoevt(&self, attr_hash: u32) -> bool {
        self.resolve_bool(attr_hash, FIELD_WNOEVT).unwrap_or(false)
    }

    /// `WNOCLM` — the raw want-no-claim dictionary flag for this attribute.
    pub fn wnoclm(&self, attr_hash: u32) -> bool {
        self.resolve_bool(attr_hash, FIELD_WNOCLM).unwrap_or(false)
    }

    /// Every system attribute for which the boolean meta-field `field_hash` is
    /// set, as `(hash, dehashed name)` sorted by name. The name is `None` for
    /// hashes outside the base-27 dehash range.
    pub fn attributes_with_flag(&self, field_hash: u32) -> Vec<(u32, Option<String>)> {
        let mut out: Vec<(u32, Option<String>)> = self
            .index
            .keys()
            .copied()
            .filter(|&h| self.resolve_bool(h, field_hash) == Some(true))
            .map(|h| (h, db1_dehash(h)))
            .collect();
        out.sort_by(|a, b| a.1.cmp(&b.1).then(a.0.cmp(&b.0)));
        out
    }

    #[cfg(test)]
    fn from_parts(
        words: Vec<u32>,
        field_ordinal: HashMap<u32, usize>,
        field_default: HashMap<u32, u32>,
        index: HashMap<u32, (usize, usize)>,
    ) -> Self {
        let syno_ordinal = field_ordinal.get(&FIELD_SYNO).copied();
        Self {
            words,
            field_ordinal,
            field_default,
            index,
            syno_ordinal,
        }
    }
}

/// Parse the system ATGTDF section into `(field hash -> 1-based ordinal,
/// field hash -> kind-2 scalar default)`. `start_page` is the Fortran
/// 1-indexed page from directory slot 0.
fn parse_atgtdf(words: &[u32], start_page: u32) -> (HashMap<u32, usize>, HashMap<u32, u32>) {
    let mut ordinal = HashMap::new();
    let mut default = HashMap::new();
    if start_page == 0 {
        return (ordinal, default);
    }
    let mut page = (start_page - 1) as usize;
    let mut count = 0usize;
    let mut done = false;
    let mut guard = 0;
    while !done && guard < 200 {
        guard += 1;
        let base = page * WORDS_PER_PAGE;
        if base + WORDS_PER_PAGE > words.len() {
            break;
        }
        let mut i = 0;
        while i + 2 < WORDS_PER_PAGE {
            let hash = words[base + i];
            if hash == DELIMITER {
                done = true;
                break;
            }
            if hash == 0 {
                break;
            }
            if !(HASH_MIN..=HASH_MAX).contains(&hash) {
                break;
            }
            let data_type = words[base + i + 1];
            let kind = words[base + i + 2];
            if !((1..=12).contains(&data_type) && (kind == 1 || kind == 2)) {
                break;
            }
            i += 3;
            let mut default_word = None;
            if kind == 2 && i < WORDS_PER_PAGE {
                if data_type == 4 {
                    // Variable-length array default: one count + count words.
                    let extra = words[base + i] as usize;
                    i += 1 + extra;
                } else {
                    default_word = Some(words[base + i]);
                    i += 1;
                }
            }
            count += 1;
            ordinal.entry(hash).or_insert(count);
            if let Some(w) = default_word {
                default.entry(hash).or_insert(w);
            }
        }
        page += 1;
    }
    (ordinal, default)
}

/// Parse the system ATGTIX section into `attribute hash -> (page, base)`.
/// `start_page` is the Fortran 1-indexed page from directory slot 2.
fn parse_atgtix(words: &[u32], start_page: u32) -> HashMap<u32, (usize, usize)> {
    let mut index = HashMap::new();
    if start_page == 0 {
        return index;
    }
    let mut page = (start_page - 1) as usize;
    let mut done = false;
    let mut guard = 0;
    while !done && guard < 4096 {
        guard += 1;
        let base = page * WORDS_PER_PAGE;
        if base + WORDS_PER_PAGE > words.len() {
            break;
        }
        let mut i = 0;
        while i + 1 < WORDS_PER_PAGE {
            let hash = words[base + i];
            if hash == DELIMITER {
                done = true;
                break;
            }
            if hash == 0 {
                break;
            }
            if hash < HASH_MIN {
                break;
            }
            let packed = words[base + i + 1] as usize;
            index.insert(hash, (packed / WORDS_PER_PAGE, packed % WORDS_PER_PAGE));
            i += 2;
        }
        page += 1;
    }
    index
}

#[cfg(test)]
mod tests {
    use super::*;

    // A hand-built record image exercising all three header dispositions.
    //
    // Records live on page 1, so `row = base - 2`.
    //   attr A (0x1000) @ base 6  -> row 4
    //     header[1]=DCHC   = 6            -> value word[row+6]=word[10]=4  (Stored)
    //     header[2]=WNOEVT = 0xFFFFFFFF   -> schema default (2 -> bool false)
    //     header[3]=SYNO   = 0            -> (unused for A)
    //   attr B (0x2000) @ base 14 -> row 12
    //     header[1]=DCHC   = 0            -> inherited; follow SYNO to A
    //     header[2]=WNOEVT = 7            -> value word[row+7]=word[19]=1  (Stored true)
    //     header[3]=SYNO   = 6            -> value word[row+6]=word[18]=A(0x1000)
    fn synthetic() -> AttrDict {
        let mut words = vec![0u32; 32];
        // attr A record (row 4)
        words[5] = 6; // header[1] DCHC offset
        words[6] = DELIMITER; // header[2] WNOEVT -> schema default
        words[7] = 0; // header[3] SYNO -> none
        words[10] = 4; // DCHC value
                       // attr B record (row 12)
        words[13] = 0; // header[1] DCHC -> inherited
        words[14] = 7; // header[2] WNOEVT offset
        words[15] = 6; // header[3] SYNO offset
        words[18] = 0x1000; // SYNO value -> parent A
        words[19] = 1; // WNOEVT value (true)

        let field_ordinal = HashMap::from([(FIELD_DCHC, 1), (FIELD_WNOEVT, 2), (FIELD_SYNO, 3)]);
        let field_default = HashMap::from([(FIELD_DCHC, 0u32), (FIELD_WNOEVT, 2u32)]);
        let index = HashMap::from([
            (0x1000u32, (1usize, 6usize)),
            (0x2000u32, (1usize, 14usize)),
        ]);
        AttrDict::from_parts(words, field_ordinal, field_default, index)
    }

    #[test]
    fn stored_value_is_read_from_record() {
        let d = synthetic();
        assert_eq!(d.resolve(0x1000, FIELD_DCHC), Some(Resolved::Stored(4)));
        assert_eq!(d.dchc(0x1000), Some(4));
    }

    #[test]
    fn schema_default_applies_when_header_is_minus_one() {
        let d = synthetic();
        // WNOEVT header is -1 for A -> schema default word 2 -> bool false.
        assert_eq!(d.resolve(0x1000, FIELD_WNOEVT), Some(Resolved::Default(2)));
        assert_eq!(d.wnoevt(0x1000), false);
    }

    #[test]
    fn inherited_field_follows_synonym_chain() {
        let d = synthetic();
        // B inherits DCHC (header 0) from its SYNO parent A, which stores 4.
        assert_eq!(d.resolve(0x2000, FIELD_DCHC), Some(Resolved::Stored(4)));
        assert_eq!(d.dchc(0x2000), Some(4));
    }

    #[test]
    fn stored_true_boolean() {
        let d = synthetic();
        assert!(d.wnoevt(0x2000));
        assert_eq!(
            d.attributes_with_flag(FIELD_WNOEVT),
            vec![(0x2000u32, None)]
        );
    }

    #[test]
    fn uda_hash_gets_schema_default_only() {
        let d = synthetic();
        // A hash beyond SYSTEM_HASH_MAX never reaches a record row.
        let uda = SYSTEM_HASH_MAX + 10;
        assert_eq!(d.resolve(uda, FIELD_DCHC), Some(Resolved::Default(0)));
        assert_eq!(d.wnoevt(uda), false);
    }

    #[test]
    fn unknown_field_is_none() {
        let d = synthetic();
        assert_eq!(d.resolve(0x1000, 0xDEAD_BEEF), None);
    }
}
