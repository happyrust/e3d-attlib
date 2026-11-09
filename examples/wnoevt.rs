//! Offline dump of the per-attribute dictionary gate fields from `attlib.dat`.
//!
//! ```text
//! cargo run --example wnoevt -- path\to\attlib.dat
//! ```
//!
//! Prints the meta-field ordinals, the WNOEVT / WNOCLM attribute sets, and a
//! small DCHC sample — the same decode the committed
//! `gen-model-model-cache/output/gen_wnoevt_flags.py` calibrates against DCHC.

use e3d_attlib::db1_hash;
use e3d_attlib::dict::{AttrDict, FIELD_DCHC, FIELD_PLCF, FIELD_WNOCLM, FIELD_WNOEVT};

fn main() {
    let path = match std::env::args().nth(1) {
        Some(p) => p,
        None => {
            eprintln!("usage: wnoevt <path-to-attlib.dat>");
            std::process::exit(2);
        }
    };

    let dict = match AttrDict::parse_file(&path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("parse {path}: {e}");
            std::process::exit(1);
        }
    };

    println!(
        "attlib: {path}\n  attributes={} fields={}",
        dict.attribute_count(),
        dict.field_count()
    );
    for (name, hash) in [
        ("WNOEVT", FIELD_WNOEVT),
        ("WNOCLM", FIELD_WNOCLM),
        ("DCHC", FIELD_DCHC),
        ("PLCF", FIELD_PLCF),
    ] {
        println!("  ordinal[{name}] = {:?}", dict.field_ordinal(hash));
    }

    for (label, field) in [("WNOEVT", FIELD_WNOEVT), ("WNOCLM", FIELD_WNOCLM)] {
        let names: Vec<String> = dict
            .attributes_with_flag(field)
            .into_iter()
            .map(|(h, n)| n.unwrap_or_else(|| format!("0x{h:08X}")))
            .collect();
        println!("\n{label}==1 ({}): {names:?}", names.len());
    }

    println!("\nDCHC sample:");
    for name in ["NAME", "POS", "ORI", "BORE", "DIAM", "HEIG"] {
        println!("  {name:6} DCHC = {:?}", dict.dchc(db1_hash(name)));
    }
}
