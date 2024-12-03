use crate::firewall::structures::Rule;
use rstest::fixture;
use std::path::PathBuf;
use std::str::FromStr;

use super::saver::Mikrotik;
use super::templates::Jinja;

//
// Various rules for building up chains
//
#[fixture]
pub fn log_rule() -> Rule {
    Rule::from_str("action=log log=yes log-prefix=foobar").unwrap()
}

#[fixture]
pub fn accept_rule() -> Rule {
    Rule::from_str("action=accept").unwrap()
}

#[fixture]
pub fn test_dir() -> PathBuf {
    let mut test_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_dir.push("resources");
    test_dir
}

#[fixture]
pub fn jinja<'a>(test_dir: PathBuf) -> Jinja<'a> {
    Jinja::new(&test_dir).unwrap()
}

#[fixture]
pub fn mikrotik() -> Mikrotik {
    Mikrotik::new()
}
