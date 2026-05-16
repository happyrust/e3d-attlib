use e3d_attlib::{AttlibData, db1_hash, db1_dehash};
use std::path::Path;

const ATTLIB_PATH: &str = r"D:\work\plant-code\pdms-io-fork\test-file\attlib.dat";

#[test]
fn parse_and_query() {
    if !Path::new(ATTLIB_PATH).exists() {
        eprintln!("SKIP: attlib.dat not found");
        return;
    }

    let data = AttlibData::parse_file(ATTLIB_PATH).expect("parse failed");

    println!("=== Attlib Parse Results ===");
    println!("  Attributes: {}", data.attributes.len());
    println!("  Nouns: {}", data.noun_attr_map.len());
    println!("  Attr defs: {}", data.attr_defs.len());
    println!("  ATNAIN entries: {}", data.noun_attr_entries.len());

    assert!(data.attributes.len() > 100, "should have many attributes");
    assert!(data.noun_attr_map.len() > 10, "should have many nouns");

    println!("\n  First 10 attributes:");
    for (i, attr) in data.attributes.iter().take(10).enumerate() {
        println!("    [{}] id={} name='{}' type={}", i, attr.id, attr.name, attr.type_code);
    }

    println!("\n  First 10 nouns:");
    let mut nouns: Vec<_> = data.list_nouns();
    nouns.sort_by_key(|(_, name)| name.clone());
    for (hash, name) in nouns.iter().take(10) {
        let attr_count = data.noun_attr_map.get(hash).map(|v| v.len()).unwrap_or(0);
        println!("    {} (0x{:08X}) -> {} attrs", name, hash, attr_count);
    }

    let test_noun = 0x000DBF71u32;
    println!("\n  Query noun_hash=0x{:08X}:", test_noun);
    if let Some(name) = db1_dehash(test_noun) {
        println!("    Name: {}", name);
    }
    let attrs = data.get_noun_attributes(test_noun);
    println!("    Attributes: {}", attrs.len());
    for (name, dtype, size) in attrs.iter().take(20) {
        println!("      {:<12} type={:<12} size={}", name, dtype, size);
    }
}

#[test]
fn parse_file_populates_attr_default_for_kind2_scalar_entries() {
    // Step 13: parse_atgtdf now fills `AttrDefEntry::default_value` for
    // ATGTDF entries with `kind == 2 && type != 4` (scalar with a
    // single-word default), per IDA `sub_55F53B8`. This test asserts
    // the auto-population kicks in on the fixture, so the e3d-io
    // ATNLOG decoder gets defaults without callers having to invoke
    // `AttlibData::set_attr_default` manually.
    if !Path::new(ATTLIB_PATH).exists() {
        eprintln!("SKIP: attlib.dat not found");
        return;
    }

    let data = AttlibData::parse_file(ATTLIB_PATH).expect("parse failed");

    let total = data.attr_defs.len();
    let kind2_total = data.attr_defs.iter().filter(|d| d.kind == 2).count();
    let kind2_type4 = data.attr_defs.iter().filter(|d| d.kind == 2 && d.data_type == 4).count();
    let kind2_scalar = data.attr_defs.iter().filter(|d| d.kind == 2 && d.data_type != 4).count();
    let with_default = data.attr_defs.iter().filter(|d| d.default_value.is_some()).count();

    println!("\n=== ATGTDF default-value coverage ===");
    println!("total entries: {total}");
    println!("kind=2 entries (have a default-pool slot): {kind2_total}");
    println!("  kind=2 type=4 (array defaults; not surfaced via AttrDefault): {kind2_type4}");
    println!("  kind=2 type!=4 (scalar defaults; auto-populated): {kind2_scalar}");
    println!("AttrDefEntry with default_value=Some(_): {with_default}");

    assert!(
        with_default > 0,
        "expected at least one attr_def with a non-None default_value after Step 13; got 0"
    );
    assert_eq!(
        with_default, kind2_scalar,
        "every kind=2 type!=4 entry must have its scalar default populated; got {with_default}/{kind2_scalar}"
    );
}
