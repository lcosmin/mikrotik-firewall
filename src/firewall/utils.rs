use indexmap::IndexSet;
use itertools::Itertools;
use once_cell::sync::Lazy;
use regex::Regex;
use std::marker::PhantomData;

/// Quote and escape the given string, if needed
pub fn escape(s: &str) -> String {
    let mut need_quotes = false;

    let mut escaped = String::with_capacity(s.len());

    for c in s.chars() {
        if !c.is_alphanumeric() {
            need_quotes = true;
        }

        match c {
            '"' => {
                escaped.push('\\');
                escaped.push('"');
            }
            _ => {
                escaped.push(c);
            }
        }
    }

    if need_quotes {
        format!("\"{}\"", escaped)
    } else {
        escaped
    }
}

pub(crate) fn valid_name(name: &str) -> bool {
    static VALIDATOR: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)^[a-z\d_\-]+$").unwrap());

    VALIDATOR.is_match(name)
}

pub struct ZoneCombiner<'a> {
    i: Box<dyn Iterator<Item = (String, String)> + 'a>,
    phahtom: PhantomData<&'a i8>,
}

impl<'a> ZoneCombiner<'a> {
    pub fn new(zones: &'a IndexSet<String>) -> Self {
        if zones.len() == 0 {
            Self {
                i: Box::new(std::iter::once((String::from(""), "".to_string()))),
                phahtom: PhantomData,
            }
        } else {
            Self {
                i: Box::new(
                    zones
                        .iter()
                        .cartesian_product(zones.iter())
                        .map(|(a, b)| (a.clone(), b.clone())),
                ),
                phahtom: PhantomData,
            }
        }
    }
}

impl<'a> Iterator for ZoneCombiner<'a> {
    type Item = (String, String);

    fn next(&mut self) -> Option<Self::Item> {
        self.i.next()
    }
}

#[cfg(test)]
mod tests {

    use super::ZoneCombiner;
    use super::{escape, valid_name};
    use assert2::check;
    use indexmap::IndexSet;
    use rstest::rstest;

    #[rstest]
    #[case("regular", "regular")]
    #[case("with space", "\"with space\"")]
    #[case("with'single'quotes", "\"with'single'quotes\"")]
    #[case("with \"double\" quotes", "\"with \\\"double\\\" quotes\"")]
    fn test_escaping(#[case] input: &str, #[case] expected: &str) {
        let result = escape(input);
        check!(result.as_str() == expected);
    }

    #[rstest]
    #[case("", false)]
    #[case(" with-leading-and-trailing-space ", false)]
    #[case("with space", false)]
    #[case("1", true)]
    #[case("input", true)]
    #[case("input_WAN", true)]
    #[case("input-WAN-2-LAN", true)]
    fn test_valid_chain_name(#[case] input: &str, #[case] expected: bool) {
        let result = valid_name(input);
        check!(result == expected);
    }

    #[rstest]
    fn test_combinator() {
        let mut m = IndexSet::new();

        let a = String::from("a");
        let b = String::from("b");

        m.insert(a.clone());
        m.insert(b.clone());

        let mut c = ZoneCombiner::new(&m);

        check!(c.next().unwrap() == (a.clone(), a.clone()));
        check!(c.next().unwrap() == (a.clone(), b.clone()));
        check!(c.next().unwrap() == (b.clone(), a.clone()));
        check!(c.next().unwrap() == (b.clone(), b.clone()));
        check!(c.next().is_none());

        let m: IndexSet<String> = IndexSet::new();

        let mut c = ZoneCombiner::new(&m);
        check!(c.next().unwrap() == ("".to_string(), "".to_string()));
        check!(c.next().is_none());
    }
}
