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
