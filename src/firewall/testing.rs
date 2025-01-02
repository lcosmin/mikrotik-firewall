use crate::firewall::rules::{Rule, RuleBuilder};
use rstest::fixture;
use std::path::PathBuf;
use std::str::FromStr;

use super::templates::Jinja;

//
// Various rules for building up chains
//
#[fixture]
pub fn log_rule() -> Rule {
    RuleBuilder::from_str("action=log log=yes log-prefix=foobar")
        .unwrap()
        .build()
        .unwrap()
}

#[fixture]
pub fn accept_rule() -> Rule {
    RuleBuilder::from_str("action=accept")
        .unwrap()
        .build()
        .unwrap()
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
