use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::hash::{db1_dehash, db1_hash};

const PAGE_SIZE: usize = 2048;
const WORDS_PER_PAGE: usize = PAGE_SIZE / 4;
const DELIMITER: u32 = 0xFFFFFFFF;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttrDataType {
    Integer,
    Real,
    Boolean,
    Reference,
    Text,
    Enum,
    Position,
    Direction,
    Orientation,
    IntArray,
    RealArray,
    RefArray,
    Unknown(u32),
}

impl AttrDataType {
    pub fn from_code(code: u32) -> Self {
        match code {
            1 => Self::Integer,
            2 => Self::Real,
            3 => Self::Boolean,
            4 => Self::Reference,
            5 => Self::Text,
            6 => Self::Enum,
            7 => Self::Position,
            8 => Self::Direction,
            9 => Self::Orientation,
            10 => Self::IntArray,
            11 => Self::RealArray,
            12 => Self::RefArray,
            v => Self::Unknown(v),
        }
    }
}

impl std::fmt::Display for AttrDataType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Integer => write!(f, "Integer"),
            Self::Real => write!(f, "Real"),
            Self::Boolean => write!(f, "Boolean"),
            Self::Reference => write!(f, "Reference"),
            Self::Text => write!(f, "Text"),
            Self::Enum => write!(f, "Enum"),
            Self::Position => write!(f, "Position"),
            Self::Direction => write!(f, "Direction"),
            Self::Orientation => write!(f, "Orientation"),
            Self::IntArray => write!(f, "IntArray"),
            Self::RealArray => write!(f, "RealArray"),
            Self::RefArray => write!(f, "RefArray"),
            Self::Unknown(v) => write!(f, "Unknown({})", v),
        }
    }
}

/// Where an [`AttributeRecord`] was discovered — the system table or the
/// UDA table within the attlib file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttrSource {
    System,
    Uda,
}

#[derive(Debug, Clone)]
pub struct AttributeRecord {
    /// PDMS hash of the attribute name (NOT a sequence id; corrected during
    /// Slice 7 — the older "id" semantics were a misreading of ATGTIX bytes).
    pub id: u32,
    pub name: String,
    pub type_code: i32,
    pub source: AttrSource,
}

#[derive(Debug, Clone, Copy)]
pub struct NounAttrEntry {
    pub noun_hash: u32,
    pub attr_index: u32,
    pub type_code: u32,
}

/// Default value for an attribute, applied when the element's storage slot
/// holds the sentinel `0xFFFFFFFF` ("use default" per IDA ATNLOG).
///
/// IDA reference (`progress.jsonl` entry #20 of goal
/// `e3d31-attribute-parsing`): when the per-element slot at ATGTDF
/// position `i` reads `0xFFFFFFFF`, the runtime resolves the value via
///
/// ```text
/// dword_6C21390[dword_6C21200[i - 1] - 1]
/// ```
///
/// — `dword_6C21200` is a per-ATGTDF-index pool index (1-based, 0 = no
/// default) and `dword_6C21390` is the value pool. The on-disk layout of
/// these two arrays in `attlib.dat` is **not yet recovered from IDA**;
/// [`AttlibData::set_attr_default`] is the runtime-injection API used by
/// tests and any future parser pass that populates the pool from
/// `attlib.dat`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AttrDefault {
    Int(i32),
    Real(f64),
    Bool(bool),
    /// Raw 32-bit word for default-pool entries the parser does not yet
    /// classify (text refs, RefNo placeholders, etc.).
    Raw(u32),
}

#[derive(Debug, Clone, Copy)]
pub struct AttrDefEntry {
    pub hash: u32,
    pub data_type: u32,
    pub kind: u32,
    pub size: u32,
    /// Default value applied when the element's slot reads `0xFFFFFFFF`.
    /// `None` means the default is not (yet) known to the parser — the
    /// decoder will surface the sentinel as a `Raw(0xFFFFFFFF)`-equivalent
    /// value in that case.
    pub default_value: Option<AttrDefault>,
}

impl AttrDefEntry {
    /// Construct an `AttrDefEntry` with `default_value = None`.
    /// Convenient for parsers and tests that don't have a default value.
    pub fn new(hash: u32, data_type: u32, kind: u32, size: u32) -> Self {
        Self { hash, data_type, kind, size, default_value: None }
    }
}

/// One entry in the ATGTIX (Attribute Index) table — the raw on-disk
/// representation parsed by IDA `sub_55F4FFC`. Each record is a 2-word
/// pair `(hash, packed_location)`.
#[derive(Debug, Clone, Copy)]
pub struct AtgtixEntry {
    pub hash: u32,
    pub page_no: u32,
    pub word_offset: u32,
}

#[derive(Debug, Clone, Default)]
pub struct AttlibData {
    pub attributes: Vec<AttributeRecord>,
    pub atgtix_entries: Vec<AtgtixEntry>,
    pub name_map: HashMap<String, usize>,
    pub noun_attr_map: HashMap<u32, Vec<u32>>,
    pub noun_attr_entries: Vec<NounAttrEntry>,
    pub attr_defs: Vec<AttrDefEntry>,
    pub attr_def_map: HashMap<u32, AttrDefEntry>,
}

impl AttlibData {
    pub fn parse_file(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref();
        let mut file = File::open(path).map_err(|e| format!("open {}: {}", path.display(), e))?;

        // Page 1 (0-indexed) is the directory page. Its first 8 words are
        // table-start pointers, laid out as recovered from IDA
        // sub_55F4290 (ATTOPE):
        //
        // ```text
        // dir[0] = system  ATGTDF start  (Fortran 1-indexed page no)
        // dir[1] =  (system block aux — unused by parsers here)
        // dir[2] = system  ATTR    start
        // dir[3] = system  ATNAIN  start
        // dir[4] = UDA     ATGTDF  start
        // dir[5] =  (UDA block aux)
        // dir[6] = UDA     ATTR    start
        // dir[7] = UDA     ATNAIN  start
        // ```
        //
        // We subtract 1 to convert Fortran 1-indexed page numbers to the
        // 0-indexed pages used by `read_page_words`.
        let dir_page = read_page_words(&mut file, 1)?;
        let to_zero_indexed = |v: u32| if v == 0 { None } else { Some((v - 1) as usize) };

        let sys_atgtdf_start = to_zero_indexed(dir_page.get(0).copied().unwrap_or(0));
        let sys_attr_start = to_zero_indexed(dir_page.get(2).copied().unwrap_or(0));
        let sys_atnain_start = to_zero_indexed(dir_page.get(3).copied().unwrap_or(0));
        let uda_atgtdf_start = to_zero_indexed(dir_page.get(4).copied().unwrap_or(0));
        let uda_attr_start = to_zero_indexed(dir_page.get(6).copied().unwrap_or(0));
        let uda_atnain_start = to_zero_indexed(dir_page.get(7).copied().unwrap_or(0));

        let mut data = AttlibData::default();

        // ATGTIX (IDA sub_55F4FFC, was misnamed "ATTR" in earlier
        // implementations) is the attribute INDEX: 2-word records mapping
        // `hash → packed_location` where `packed = page * 512 + word_offset`.
        // It contains NO name strings. We synthesize an AttributeRecord per
        // entry, resolving the name via system_names lookup (for system
        // hashes) or db1_dehash (for short UDA hashes that happen to land
        // in the base-27 range); UDAs with hash > 0x171FAD39 yield empty
        // names here — a full UDA-name follow-on (Slice 7 follow-up) would
        // read the name string at the indicated (page, word_offset).
        for (table_kind, start_opt) in
            [("system", sys_attr_start), ("uda", uda_attr_start)]
        {
            if let Some(start) = start_opt {
                let entries = parse_atgtix(&mut file, start)?;
                for entry in entries {
                    let idx = data.attributes.len();
                    let name = resolve_attr_name(entry.hash);
                    data.atgtix_entries.push(entry);
                    if !name.is_empty() {
                        data.name_map.insert(name.clone(), idx);
                    }
                    data.attributes.push(AttributeRecord {
                        id: entry.hash,
                        name,
                        type_code: 0,
                        // Tag where this came from so downstream callers
                        // can distinguish system vs UDA.
                        source: if table_kind == "uda" {
                            AttrSource::Uda
                        } else {
                            AttrSource::System
                        },
                    });
                }
            }
        }

        // ATGTSX (IDA sub_55F594C, was misnamed "ATNAIN" in earlier
        // implementations) is a 3-word-per-record series. The first word
        // is the noun hash, the second and third are interpreted as
        // (attr_hash_or_index, type_code) for compatibility with the old
        // public `NounAttrEntry` shape. Note: the precise semantics of
        // word[1]/word[2] are still being recovered — the old code's
        // `attr_idx` value may not be the literal index into ATGTIX.
        for start in [sys_atnain_start, uda_atnain_start].into_iter().flatten() {
            parse_atgtsx(&mut file, start, &mut data)?;
        }

        // Parse system ATGTDF followed by UDA ATGTDF.
        for start in [sys_atgtdf_start, uda_atgtdf_start].into_iter().flatten() {
            parse_atgtdf(&mut file, start, &mut data)?;
        }

        data.build_attr_def_map();

        Ok(data)
    }

    fn build_attr_def_map(&mut self) {
        for def in &self.attr_defs {
            self.attr_def_map.insert(def.hash, *def);
        }
    }

    pub fn get_noun_name(&self, noun_hash: u32) -> Option<String> {
        db1_dehash(noun_hash)
    }

    pub fn get_attr_name(&self, attr_index: u32) -> Option<&str> {
        self.attributes.get(attr_index as usize).map(|a| a.name.as_str())
    }

    pub fn get_noun_attributes(&self, noun_hash: u32) -> Vec<(&str, AttrDataType, u32)> {
        let indices = match self.noun_attr_map.get(&noun_hash) {
            Some(v) => v,
            None => return vec![],
        };

        let mut result = Vec::new();
        for &idx in indices {
            if let Some(attr) = self.attributes.get(idx as usize) {
                let hash = db1_hash(&attr.name);
                let (dtype, size) = if let Some(def) = self.attr_def_map.get(&hash) {
                    (AttrDataType::from_code(def.data_type), def.size)
                } else {
                    (AttrDataType::Unknown(0), 1)
                };
                result.push((attr.name.as_str(), dtype, size));
            }
        }
        result
    }

    pub fn list_nouns(&self) -> Vec<(u32, String)> {
        self.noun_attr_map
            .keys()
            .filter_map(|&h| db1_dehash(h).map(|name| (h, name)))
            .collect()
    }

    /// Position of an attribute in the ATGTDF table (1-based), matching
    /// what IDA `sub_5392270` would return. Used by the `ATNLOG`-style
    /// byte decoder (`e3d-io`) to compute the element-record slot offset.
    ///
    /// Returns `None` if the attribute is not in the ATGTDF table.
    pub fn atgtdf_position(&self, attr_hash: u32) -> Option<usize> {
        self.attr_defs
            .iter()
            .position(|def| def.hash == attr_hash)
            .map(|idx| idx + 1)
    }

    /// Iterator over ATGTDF entries with duplicate hashes filtered out.
    /// Keeps the FIRST occurrence of each hash (which corresponds to the
    /// smallest `atgtdf_position`, which `atgtdf_position(hash)` returns).
    ///
    /// The on-disk ATGTDF can contain duplicate hash entries for system
    /// attributes that appear in both the per-installation default set
    /// and the project-specific overrides. For an attribute-resolution
    /// pipeline that uses `atgtdf_position(hash)`, the second occurrence
    /// is structurally unreachable, so iterating attr_defs without
    /// dedup will re-decode the same slot multiple times.
    pub fn attr_defs_unique(&self) -> impl Iterator<Item = &AttrDefEntry> {
        let mut seen = std::collections::HashSet::with_capacity(self.attr_defs.len());
        self.attr_defs.iter().filter(move |def| seen.insert(def.hash))
    }

    /// Convenience: get the `AttrDefEntry` for a hash directly.
    pub fn attr_def(&self, attr_hash: u32) -> Option<&AttrDefEntry> {
        self.attr_def_map.get(&attr_hash)
    }

    /// Inject a default value for an attribute hash, updating both
    /// `attr_defs` (the canonical vector) and `attr_def_map` (the lookup
    /// shortcut) so subsequent calls to [`attr_def`] see the same value.
    ///
    /// Returns `true` when at least one matching `AttrDefEntry` was
    /// updated; `false` when the hash is not present in `attr_defs`.
    ///
    /// This is the runtime-injection API for the default-value pool
    /// described on [`AttrDefault`]. Tests use it to validate the decoder
    /// pipeline end-to-end; a future ATGTDF default-pool parser pass
    /// will call this internally once the on-disk layout in `attlib.dat`
    /// is recovered from IDA.
    ///
    /// [`attr_def`]: AttlibData::attr_def
    pub fn set_attr_default(&mut self, attr_hash: u32, default: AttrDefault) -> bool {
        let mut found = false;
        for def in self.attr_defs.iter_mut() {
            if def.hash == attr_hash {
                def.default_value = Some(default);
                found = true;
            }
        }
        if let Some(entry) = self.attr_def_map.get_mut(&attr_hash) {
            entry.default_value = Some(default);
        }
        found
    }
}

fn read_page_words(file: &mut File, page_no: usize) -> Result<Vec<u32>, String> {
    let offset = page_no * PAGE_SIZE;
    file.seek(SeekFrom::Start(offset as u64))
        .map_err(|e| format!("seek page {}: {}", page_no, e))?;

    let mut buf = vec![0u8; PAGE_SIZE];
    file.read_exact(&mut buf)
        .map_err(|e| format!("read page {}: {}", page_no, e))?;

    parse_page_words(&buf)
        .map_err(|_| format!("parse page {} failed", page_no))
}

fn parse_page_words(input: &[u8]) -> Result<Vec<u32>, String> {
    use nom::multi::count;
    use nom::number::complete::be_u32;
    use nom::Parser;

    let result: nom::IResult<&[u8], Vec<u32>> = count(be_u32, WORDS_PER_PAGE).parse(input);
    result
        .map(|(_, words)| words)
        .map_err(|e| format!("nom parse error: {:?}", e))
}

/// Resolve a system attribute hash to a human-readable name.
///
/// Order of preference:
///
/// 1. `crate::system_names::lookup_by_hash` — the 6377-entry static table
///    extracted from `core.dll` (`?ATT_<NAME>@@3...` symbols).
/// 2. `db1_dehash(hash)` — for short names inside the base-27 range that
///    don't appear in the static table.
/// 3. Empty string for UDA hashes (`hash > 0x171FAD39`) — recovering UDA
///    names requires following the ATGTIX `(page, word_offset)` pointer to
///    read a length-prefixed string (Slice 7 follow-up).
fn resolve_attr_name(hash: u32) -> String {
    if let Some(s) = crate::system_names::lookup_by_hash(hash) {
        return s.to_string();
    }
    db1_dehash(hash).unwrap_or_default()
}

/// Parse the ATGTIX (Attribute Index) table.
///
/// IDA reference: `sub_55F4FFC` (`exprlib/ATGTIX`). Each record is two
/// big-endian 32-bit words:
///
/// * word\[0] = `hash` (in `[0x81BF2, 0x171FAD39]` for system attributes,
///   or above the upper bound for UDAs)
/// * word\[1] = `packed = page_no * 512 + word_offset_within_page`
///
/// Termination follows the same convention as `sub_55F4FFC`: a leading
/// `hash == 0` ends the current page (advance to next); `hash ==
/// 0xFFFFFFFF` ends the table.
fn parse_atgtix(file: &mut File, start_page: usize) -> Result<Vec<AtgtixEntry>, String> {
    let mut out = Vec::new();
    let mut reached_delimiter = false;
    for page_idx in start_page..start_page + 1024 {
        if reached_delimiter {
            break;
        }
        let words = match read_page_words(file, page_idx) {
            Ok(w) => w,
            Err(_) => break,
        };
        let mut i = 0usize;
        while i + 1 < words.len() {
            let hash = words[i];
            if hash == DELIMITER {
                reached_delimiter = true;
                break;
            }
            if hash == 0 {
                break;
            }
            // IDA's `sub_55F4FFC` would error on out-of-range hash; we
            // forgive and stop reading the current page.
            if !(531_442..=0xFFFF_FFFF).contains(&hash) {
                break;
            }
            let packed = words[i + 1];
            out.push(AtgtixEntry {
                hash,
                page_no: packed / 512,
                word_offset: packed % 512,
            });
            i += 2;
        }
    }
    Ok(out)
}

/// Parse the ATGTSX series table.
///
/// IDA reference: `sub_55F594C` (`exprlib/ATGTSX`). Each record is three
/// big-endian 32-bit words. The current best interpretation is
/// `(noun_hash, attr_hash_or_idx, type_code)`; precise word\[1] semantics
/// are pending Slice 7 follow-up.
///
/// Termination matches `sub_55F594C`: word\[0] == 0 ends the current page;
/// word\[0] == DELIMITER ends the table.
fn parse_atgtsx(file: &mut File, start_page: usize, data: &mut AttlibData) -> Result<(), String> {
    let mut reached_delimiter = false;
    for page_idx in start_page..start_page + 1024 {
        if reached_delimiter {
            break;
        }
        let words = match read_page_words(file, page_idx) {
            Ok(w) => w,
            Err(_) => break,
        };

        let mut i = 0usize;
        while i + 2 < words.len() {
            let w0 = words[i];
            if w0 == DELIMITER {
                reached_delimiter = true;
                break;
            }
            if w0 == 0 {
                break;
            }
            let noun_hash = w0;
            let attr_idx = words[i + 1];
            let type_code = words[i + 2];
            i += 3;

            // attr_idx of 0 or huge values are likely structural noise.
            if attr_idx == 0 {
                continue;
            }

            data.noun_attr_map
                .entry(noun_hash)
                .or_default()
                .push(attr_idx);

            data.noun_attr_entries.push(NounAttrEntry {
                noun_hash,
                attr_index: attr_idx,
                type_code,
            });
        }
    }
    Ok(())
}

/// Locate the start of the ATGTDF table inside the attlib file by
/// structural pattern matching.
///
/// Strategy: scan every page in the file and rank each by the longest run
/// of records that match the IDA reference structure (`sub_55F53B8`):
///
/// * `hash` ∈ `[0x81BF2, 0x171FAD39]` (base-27 PDMS hash range)
/// * `type` ∈ `[1, 12]` (`DB_Attribute::type`; see `EXMAP_dispatch` in
///   `docs/ida-3.1-attributes.md` §3)
/// * `kind` ∈ `{1, 2}` (1 = scalar, 2 = sized; any other value would cause
///   `sub_55F53B8` to abort with an error)
///
/// The returned page has the largest such run (must be ≥ 5 to qualify).
///
/// Not currently called by `parse_file` (which uses the authoritative
/// directory-page slots recovered from IDA `sub_55F4290`/ATTOPE); kept as
/// a diagnostic / fallback for corrupt or unknown attlib layouts.
#[allow(dead_code)]
fn guess_atgtdf_start(file: &mut File, _candidates: &[usize]) -> Option<usize> {
    let file_len = file.metadata().ok()?.len();
    let total_pages = (file_len as usize) / PAGE_SIZE;
    if total_pages == 0 {
        return None;
    }

    let mut best: Option<(usize, u32)> = None;
    for page_no in 0..total_pages {
        let words = match read_page_words(file, page_no) {
            Ok(w) => w,
            Err(_) => continue,
        };
        let run = longest_atgtdf_run(&words);
        if run >= 5 {
            match best {
                Some((_, b)) if b >= run => {}
                _ => best = Some((page_no, run)),
            }
        }
    }
    best.map(|(p, _)| p)
}

#[allow(dead_code)]
fn longest_atgtdf_run(words: &[u32]) -> u32 {
    let mut max_run = 0u32;
    let mut run = 0u32;
    let mut i = 0usize;
    while i + 2 < words.len() {
        let hash = words[i];
        let ty = words[i + 1];
        let kind = words[i + 2];
        let ok = (531_442..=387_951_929).contains(&hash)
            && (1..=12).contains(&ty)
            && (kind == 1 || kind == 2);
        if ok {
            run += 1;
            if run > max_run {
                max_run = run;
            }
            // Walk past optional size words so the next triple aligns.
            let step = if kind == 2 {
                if ty == 4 {
                    // Variable-length array variant: count + count words.
                    // Treat conservatively — only step past the count word
                    // here; if the array data isn't well-formed the next
                    // triple will fail validation and run resets.
                    if i + 3 < words.len() {
                        let n = words[i + 3] as usize;
                        4 + n
                    } else {
                        3
                    }
                } else {
                    4
                }
            } else {
                3
            };
            i += step;
        } else {
            run = 0;
            i += 1;
        }
    }
    max_run
}

fn parse_atgtdf(file: &mut File, start_page: usize, data: &mut AttlibData) -> Result<(), String> {
    // IDA reference: sub_55F53B8 (`exprlib/ATGTDF`). Records are (hash,
    // type, kind) triples. `kind==1` ⇒ scalar (no extra word); `kind==2`
    // ⇒ sized — one extra `size` word, or for `type==4` a count + count
    // words. Hash range is the documented PDMS base-27 dehash band.
    //
    // Termination: hash == 0 means "no more records on this page; advance
    // to the next page"; hash == 0xFFFFFFFF (DELIMITER) means "end of the
    // ATGTDF table". Any other out-of-range value is treated as a hard
    // stop (the IDA original raises an MR_Message error).
    let mut reached_delimiter = false;
    for page_idx in start_page..start_page + 100 {
        if reached_delimiter {
            break;
        }
        let words = match read_page_words(file, page_idx) {
            Ok(w) => w,
            Err(_) => break,
        };

        let mut i = 0;
        while i + 2 < words.len() {
            let w0 = words[i];
            if w0 == DELIMITER {
                reached_delimiter = true;
                break;
            }
            if w0 == 0 {
                break;
            }
            if !(531_442..=387_951_929).contains(&w0) {
                // Out-of-range hash — treat as a hard stop for this page
                // (the IDA original errors out; we are intentionally more
                // forgiving to keep the rest of the file parseable).
                break;
            }
            let w1 = words[i + 1];
            let kind = words[i + 2];
            // Strict shape check: only accept records the IDA original
            // would have accepted. Anything else is structural noise.
            if !((1..=12).contains(&w1) && (kind == 1 || kind == 2)) {
                break;
            }
            i += 3;

            let mut size = 1u32;
            if kind == 2 && i < words.len() {
                if w1 == 4 {
                    if i < words.len() {
                        let n = words[i];
                        size = n;
                        i += 1 + n as usize;
                    }
                } else {
                    size = words[i];
                    i += 1;
                }
            }

            data.attr_defs.push(AttrDefEntry::new(w0, w1, kind, size));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attr_def_entry_new_yields_none_default() {
        let e = AttrDefEntry::new(0x123, 1, 1, 1);
        assert_eq!(e.hash, 0x123);
        assert_eq!(e.data_type, 1);
        assert_eq!(e.kind, 1);
        assert_eq!(e.size, 1);
        assert!(e.default_value.is_none());
    }

    #[test]
    fn set_attr_default_updates_both_vector_and_map() {
        let mut a = AttlibData::default();
        a.attr_defs.push(AttrDefEntry::new(0x111, 1, 1, 1));
        a.attr_defs.push(AttrDefEntry::new(0x222, 2, 1, 1));
        a.build_attr_def_map();

        assert!(a.set_attr_default(0x111, AttrDefault::Int(42)));
        let from_vec = a.attr_defs.iter().find(|d| d.hash == 0x111).unwrap();
        let from_map = a.attr_def(0x111).unwrap();
        assert_eq!(from_vec.default_value, Some(AttrDefault::Int(42)));
        assert_eq!(from_map.default_value, Some(AttrDefault::Int(42)));
        assert!(a.attr_def(0x222).unwrap().default_value.is_none());
    }

    #[test]
    fn set_attr_default_returns_false_when_hash_unknown() {
        let mut a = AttlibData::default();
        a.attr_defs.push(AttrDefEntry::new(0x111, 1, 1, 1));
        a.build_attr_def_map();
        assert!(!a.set_attr_default(0xDEADBEEF, AttrDefault::Bool(true)));
        assert!(a.attr_def(0xDEADBEEF).is_none());
    }

    #[test]
    fn set_attr_default_handles_duplicate_hashes() {
        let mut a = AttlibData::default();
        a.attr_defs.push(AttrDefEntry::new(0x111, 1, 1, 1));
        a.attr_defs.push(AttrDefEntry::new(0x111, 1, 1, 1));
        a.build_attr_def_map();
        assert!(a.set_attr_default(0x111, AttrDefault::Real(3.14)));
        for def in &a.attr_defs {
            assert_eq!(def.default_value, Some(AttrDefault::Real(3.14)));
        }
    }
}
