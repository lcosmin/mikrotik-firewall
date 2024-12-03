use once_cell::sync::Lazy;
use regex::Regex;

pub fn valid_chain_name(name: &str) -> bool {
    static VALIDATOR: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)^[a-z\d_\-]+$").unwrap());

    VALIDATOR.is_match(name)
}

/// Quote and escape the given string, if needed
pub fn escape(s: &str) -> String {
    let mut need_quotes = false;

    let mut escaped = String::with_capacity(s.len());

    for c in s.chars() {
        match c {
            ' ' => {
                need_quotes = true;
                escaped.push(c);
            }
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

#[cfg(test)]
mod tests {

    use super::{escape, valid_chain_name};
    use assert2::check;
    use rstest::rstest;

    #[rstest]
    #[case("regular", "regular")]
    #[case("with space", "\"with space\"")]
    #[case("with'single'quotes", "with'single'quotes")]
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
        let result = valid_chain_name(input);
        check!(result == expected);
    }
}
