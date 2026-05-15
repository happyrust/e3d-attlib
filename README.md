# e3d-attlib

Standalone parser for AVEVA E3D 3.1 / PDMS `attlib.dat` attribute library files. Provides the **attribute schema** (ATGTIX index, ATGTDF type definitions, ATGTSX noun-attribute series), the PDMS **base-27 name hash** (`db1_hash` / `db1_dehash`), the **EXMAP dispatch** for `(DB_Attribute::type, size, ityp, isUDA) → DBE_Base::expType`, and a static **6377-entry system attribute name table** extracted from `core.dll` global symbols.

Used as the schema layer by [`e3d-io`](../e3d-io/README.md) for attribute resolution.

Reverse-engineered from `core.dll` via IDA Pro; field offsets, constants, and dispatch rules cite IDA evidence.

## Status

- **ATTOPE dir-page parsing**: 8-slot directory page identifies system + UDA blocks for ATGTDF / ATGTIX / ATGTSX (replaces the earlier mis-named "ATTR / ATNAIN" approach).
- **ATGTIX parser**: 2-word records `(hash, packed_location)` where `packed = page * 512 + word_offset`.
- **ATGTDF parser**: 3-word records `(hash, data_type, kind)` with extension semantics for `kind=2`.
- **ATGTSX parser**: 3-word records (noun-attribute series).
- **EXMAP dispatch**: full IDA `sub_51D368F` table reproduced, including the `type==1 size==1 → Integer` and `type==2 size==1 → RealScalar` refinements (the IDA-literal codomain doesn't distinguish these; `e3d-attlib` does so its decoder can pick the correct reader).
- **System name lookup**: 6377-entry static table extracted from `core.dll`'s `?ATT_<NAME>@@3...` global symbols. Binary-search by hash, O(log n).
- **Hash round-trip**: `db1_hash` / `db1_dehash` validated against IDA `PDMS_Hash::String` at `0x588cb87`.

## Dependencies

- `thiserror = "2"` — error enums
- `nom = "8"` — binary parsing

No other dependencies. No external native libraries (no `aws-lc-sys`, no `surrealdb`, etc.).

## Quick start

```rust
use e3d_attlib::{AttlibData, db1_hash, db1_dehash, lookup_system_name, exmap_dispatch};

let attlib = AttlibData::parse_file(r"path\to\attlib.dat")?;

println!("ATGTIX entries: {}", attlib.atgtix_entries.len());
println!("ATGTDF entries: {}", attlib.attr_defs.len());
println!("ATGTSX entries: {}", attlib.noun_attr_entries.len());

// Find an attribute by hash:
let bore_hash = db1_hash("BORE");  // base-27 PDMS name hash
if let Some(def) = attlib.attr_def(bore_hash) {
    println!("BORE: data_type={} kind={} size={}", def.data_type, def.kind, def.size);
}

// Round-trip a hash back to a name:
let name = db1_dehash(0x0009E770);  // -> Some("SIZE")
println!("0x0009E770 = {:?}", name);

// EXMAP dispatch:
let exp_type = exmap_dispatch(/* type */ 2, /* size */ 1, /* ityp */ 0, /* isUDA */ false);
// -> Some(ExpType::RealScalar)
```

## API surface

| Type / fn | Purpose |
|---|---|
| `AttlibData::parse_file(path)` | Parse the entire attlib.dat |
| `AttlibData::attr_def(hash)` | Look up ATGTDF entry by hash |
| `AttlibData::atgtdf_position(hash)` | 1-based position in ATGTDF (used for record-slot indexing) |
| `lookup_system_name(hash)` | Static-table lookup (6377 system attributes) |
| `db1_hash(name)` / `db1_dehash(hash)` | PDMS base-27 name hash |
| `is_system_hash(hash)` | True when `hash <= 0x171FAD39` (the base-27 dehash range) |
| `exmap_dispatch(ty, size, ityp, is_uda)` | `(type, size, ityp, isUDA) → ExpType` dispatch (IDA `sub_51D368F`) |
| `ExpType` | Semantic value type enum (15 variants: Boolean / Integer / RealScalar / Text / DbRef / Position / Direction / Orientation / arrays / Blob) |

## License

(Add as needed.)
