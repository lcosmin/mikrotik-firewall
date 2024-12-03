use anyhow::{anyhow, Result};
use pest::Parser;
use pest_derive::Parser;
use tracing::error;

use super::structures;
use super::templates::Jinja;

#[derive(Parser)]
#[grammar = "firewall/parser.pest"]
pub struct RuleParser;

#[derive(Debug, PartialEq)]
pub enum Token<'a> {
    Key(&'a str),
    KeyValue(&'a str, &'a str),
}

/// Parses a firewall rule from the configuration file into a vector of Tokens
pub fn tokenize_rule_line<'a>(line: &'a str) -> Result<Vec<Token<'a>>> {
    let line = RuleParser::parse(Rule::line, line)?.next().expect("line");

    let mut result: Vec<Token> = Vec::new();

    for l in line.into_inner() {
        match l.as_rule() {
            Rule::item => {
                let item = l.into_inner().next().unwrap();
                // println!("item: {:?}", item);

                match item.as_rule() {
                    Rule::key => {
                        result.push(Token::Key(item.as_str()));
                    }
                    Rule::key_value => {
                        let mut inner = item.into_inner();

                        let key = inner.next().unwrap().as_str();

                        // inner.next is the "value" from the key_value rule.
                        // into_inner.next gets to the inner rule and we can test there
                        // if it's a plain value or quoted value
                        let value = inner.next().unwrap().into_inner().next().unwrap();

                        match value.as_rule() {
                            Rule::plain_value => result.push(Token::KeyValue(key, value.as_str())),
                            Rule::quoted_value =>
                            // Need to get to the unquoted value because we store that
                            {
                                result.push(Token::KeyValue(
                                    key,
                                    value.into_inner().next().unwrap().as_str(),
                                ))
                            }

                            _ => {
                                panic!("unexpected rule in key_value");
                            }
                        }
                    }
                    _ => error!("unexpected item type"),
                }
            }
            Rule::EOI => {}
            _ => error!("unexpected type"),
        }
    }

    Ok(result)
}

/// Expands the given string using Jinja, then attempts to parse a [Rule] out of
/// the result.
pub fn expand_string_and_parse_rule(
    jinja: &Jinja,
    ctx: Option<&minijinja::Value>,
    r: &str,
) -> Result<structures::Rule> {
    let rule_line = match ctx {
        Some(c) => jinja.expand_template(c, r)?,
        None => r.to_owned(),
    };

    // Parse the line into tokens

    let Ok(tokens) = tokenize_rule_line(&rule_line) else {
        return Err(anyhow!("error parsing line: {:?}", &rule_line));
    };

    // ...compile the rule
    let Ok(rule) = structures::Rule::from_tokens(&tokens) else {
        return Err(anyhow!("error building rule from {:?}", &tokens));
    };

    // ...and validate it
    if !rule.is_valid() {
        return Err(anyhow!("tried to compile an invalid rule: {:?}", &rule));
    }

    Ok(rule)
}

#[cfg(test)]
mod tests {

    use super::{expand_string_and_parse_rule, tokenize_rule_line, Token};
    use crate::firewall::saver::{FirewallSerializer, Mikrotik};
    use crate::firewall::templates::Jinja;
    use crate::firewall::testing::{jinja, mikrotik};
    use assert2::check;
    use minijinja::context;
    use rstest::rstest;

    #[test]
    fn test_tokenize_rule_line() {
        let res = tokenize_rule_line("");
        assert!(res.is_err());

        let res = tokenize_rule_line("-");
        assert!(res.is_err());

        let res = tokenize_rule_line("asd-");
        assert!(res.is_err());

        let res = tokenize_rule_line("foo").unwrap();
        check!(res == vec![Token::Key("foo")]);

        let res = tokenize_rule_line("foo bar").unwrap();
        check!(res == vec![Token::Key("foo"), Token::Key("bar")]);

        let res = tokenize_rule_line("foo-bar bar-foo=\"foo=bar\" blax").unwrap();
        check!(
            res == vec![
                Token::Key("foo-bar"),
                Token::KeyValue("bar-foo", "foo=bar"),
                Token::Key("blax"),
            ]
        );
    }

    #[rstest]
    fn test_expand_string_and_parse_rule(jinja: Jinja<'_>, mikrotik: Mikrotik) {
        let ctx = context! {
            name => "foo",
        };

        // Invalid: Jinja causes an error
        let s = "{{ invalid".to_string();
        let res = expand_string_and_parse_rule(&jinja, Some(&ctx), &s);
        check!(res.is_err());

        // Invalid: line causes an error
        let s = "";
        let res = expand_string_and_parse_rule(&jinja, Some(&ctx), &s);
        check!(res.is_err());

        // Invalid: rule fails to compile
        let s = "action=unknown";
        let res = expand_string_and_parse_rule(&jinja, Some(&ctx), &s);
        check!(res.is_err());

        // Invalid: rule is incomplete
        let s = "action=jump";
        let res = expand_string_and_parse_rule(&jinja, Some(&ctx), &s);
        check!(res.is_err());

        // Valid rule
        let s = "action=accept comment={{name}}";
        let res = expand_string_and_parse_rule(&jinja, Some(&ctx), &s).unwrap();
        // Check that the template got expanded
        check!(mikrotik.serialize_rule(&res).unwrap().as_str() == "action=accept comment=foo");

        // Valid rule but without jinja expansion (for better coverage)
        let s = "action=accept comment={{name}}";
        let res = expand_string_and_parse_rule(&jinja, None, &s).unwrap();
        check!(mikrotik.serialize_rule(&res).unwrap().as_str() == "action=accept comment={{name}}");
    }
}
