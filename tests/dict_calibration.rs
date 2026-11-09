//! Calibration of the offline dictionary decoder ([`e3d_attlib::dict`])
//! against a real `attlib.dat`.
//!
//! Skips cleanly when the fixture is absent (CI has no `attlib.dat`). The
//! asserted ground truth is the subset that is identical across two
//! independent E3D 3.1 dictionaries, so the test is portable to whichever
//! 3.1 `attlib.dat` is present:
//!
//! * meta-field ordinals DCHC=49, PLCF=50, WNOEVT=28, WNOCLM=29;
//! * DCHC change classes for stable core attributes (POS/ORI=3, geometry=4,
//!   NAME=0, HBOR=1, TBOR=2);
//! * the WNOEVT gate on the laser/lighting/temperature attributes shared by
//!   both dictionaries, and never on a model-generation attribute.
//!
//! The exhaustive parity check (all 4270 DCHC + 58 PLCF names) lives in the
//! committed generator `gen-model-model-cache/output/gen_wnoevt_flags.py`,
//! which reuses this exact decode.

use std::collections::HashSet;
use std::path::Path;

use e3d_attlib::db1_hash;
use e3d_attlib::dict::{AttrDict, FIELD_DCHC, FIELD_PLCF, FIELD_WNOCLM, FIELD_WNOEVT};

const ATTLIB_PATH: &str = r"D:\work\plant-code\pdms-io-fork\test-file\attlib.dat";

#[test]
fn decodes_dchc_plcf_and_the_wnoevt_gate() {
    if !Path::new(ATTLIB_PATH).exists() {
        eprintln!("SKIP: attlib.dat not found at {ATTLIB_PATH}");
        return;
    }

    let dict = AttrDict::parse_file(ATTLIB_PATH).expect("parse attlib.dat");
    assert!(
        dict.attribute_count() > 1000,
        "expected the full system attribute index, got {}",
        dict.attribute_count()
    );

    // Meta-field ordinals are fixed by the E3D 3.1 ATGTDF schema.
    assert_eq!(dict.field_ordinal(FIELD_WNOEVT), Some(28));
    assert_eq!(dict.field_ordinal(FIELD_WNOCLM), Some(29));
    assert_eq!(dict.field_ordinal(FIELD_DCHC), Some(49));
    assert_eq!(dict.field_ordinal(FIELD_PLCF), Some(50));

    // DCHC ground truth verified identical in two independent 3.1 dictionaries.
    for (name, want) in [
        ("NAME", 0),
        ("POS", 3),
        ("ORI", 3),
        ("BORE", 4),
        ("DIAM", 4),
        ("HEIG", 4),
        ("HBOR", 1),
        ("TBOR", 2),
    ] {
        assert_eq!(
            dict.dchc(db1_hash(name)),
            Some(want),
            "DCHC({name}) should be {want}"
        );
    }

    // The WNOEVT gate: attributes whose put fires no change event. These
    // laser / lighting / temperature attributes are set in both dictionaries.
    let wnoevt_names: HashSet<String> = dict
        .attributes_with_flag(FIELD_WNOEVT)
        .into_iter()
        .filter_map(|(_, name)| name)
        .collect();
    for name in ["DPOSCA", "LIGTCA", "LIGTCP", "TEMPLI", "EVITCA", "EVITCP"] {
        assert!(
            wnoevt_names.contains(name),
            "WNOEVT should be set on {name}; decoded set = {wnoevt_names:?}"
        );
    }
    // No model-generation attribute is silent.
    for name in ["BORE", "POS", "ORI", "NAME", "DIAM", "HEIG"] {
        assert!(
            !dict.wnoevt(db1_hash(name)),
            "WNOEVT must not be set on model attribute {name}"
        );
    }

    // The per-attribute WNOEVT set is small (a handful), not the whole schema.
    assert!(
        wnoevt_names.len() < 200,
        "WNOEVT set unexpectedly large ({}), suspect an ordinal/index bug",
        wnoevt_names.len()
    );
}
