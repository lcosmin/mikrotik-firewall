use super::parser::{tokenize_rule_line, Token};
use super::structures;

use anyhow::{anyhow, Result};
use indexmap::IndexMap;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::str::FromStr;
use tracing::debug;

/// Type alias for firewall policies
pub(crate) type Policies = HashMap<String, Policy>;

#[derive(Debug)]
pub(crate) struct Policy {
    pub rules: Vec<Rule>,
}

impl Policy {
    pub fn new() -> Self {
        Self { rules: vec![] }
    }
}

/// Type alias for firewall tables
pub(crate) type Tables = IndexMap<String, Table>;

/// Firewall table. Contains one or multiple chains
#[derive(Clone, Debug)]
pub(crate) struct Table {
    pub chains: IndexMap<String, Chain>,
}

impl Table {
    pub fn new() -> Self {
        Self {
            chains: IndexMap::new(),
        }
    }
}

/// Firewall chain. Contains one or multiple rules
#[derive(Clone, Debug)]
pub(crate) struct Chain {
    pub rules: Vec<Rule>,
    pub name: String,

    /// Indicates that this chain does not return; value is filled after optimizing
    pub is_final: bool,
    pub has_unconditional_return: bool,
}

impl Chain {
    pub fn new(name: &str) -> Self {
        Self {
            rules: vec![],
            name: name.to_string(),
            is_final: false,
            has_unconditional_return: false,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn add_rule(&mut self, r: Rule) {
        self.rules.push(r);
    }
}

/// A parameter for a [Rule]
#[warn(unused)]
#[derive(Clone, Debug, PartialEq)]
pub enum Parameter {
    NoValue(String),
    Value(String, String),
}

/// Firewall rule
#[derive(Clone, Debug, PartialEq)]
pub struct Rule {
    pub action: Option<Action>,
    pub jump_target: Option<String>,
    pub params: Vec<Parameter>, // TODO: should be a map to avoid duplicates; also for fast searching
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut items: Vec<String> = Vec::new();

        if let Some(ref action) = self.action {
            items.push(format!("action={}", action.as_str()));
        } else {
            items.push("action=n/a".to_string());
        }

        if let Some(ref jump_target) = self.jump_target {
            items.push(format!("jump-target={}", jump_target));
        }

        for p in self.params.iter() {
            match p {
                Parameter::NoValue(name) => items.push(name.clone()),
                Parameter::Value(name, value) => items.push(format!("{}={}", &name, &value)),
            }
        }

        write!(f, "{}", items.join(" "))?;

        Ok(())
    }
}

impl Rule {
    /// Builds a [Rule] from a parsed vector of [Token]
    pub fn from_tokens<'a>(v: &Vec<Token<'a>>) -> Result<Self> {
        let mut rule = Rule {
            action: None,
            jump_target: None,
            params: Vec::new(),
        };

        for tok in v.iter() {
            match tok {
                Token::Key(k) => rule.params.push(Parameter::NoValue(k.to_string())),
                Token::KeyValue(k, v) => match *k {
                    "action" => rule.action = Some(Action::from_str(v)?),
                    "jump-target" => rule.jump_target = Some(v.to_string()),
                    _ => rule.params.push(Parameter::Value(k.to_string(), v.to_string())),
                },
            }
        }

        Ok(rule)
    }

    pub fn from_str(s: &str) -> Result<Self> {

        let tokens = tokenize_rule_line(s)?;
  
        // ...compile the rule
        structures::Rule::from_tokens(&tokens)
    }

    /// Checks if the rule is valid
    pub fn is_valid(&self) -> bool {
        // TODO: put this in `from_tokens` ?
        // TODO: make it `validate() -> Result<()>` to return a more comprehensive error about why
        // it's invalid?
        if let Some(ref act) = self.action {
            if *act == Action::Jump && self.jump_target.is_none() {
                return false;
            }
            return true;
        }
        false // must have an action
    }

    /// Checks if this rule is a jump rule
    pub fn is_jump(&self) -> bool {
        if let Some(ref act) = self.action {
            if *act == Action::Jump {
                return true;
            }
        }
        false
    }

    pub fn is_disabled(&self) -> bool {
        // TODO: add methods for adding parameters to a rule and use bools instead
        // of functions for is_disabled and such , and they get updated when a param
        // is added ?
        for p in self.params.iter() {

            match p {
                Parameter::NoValue(_) => {},
                Parameter::Value(ref name, ref value) => {
                    if name != "disabled" {
                        continue
                    }
                    return value == "yes";
                }
            }
        }

        false
    }

    /// Checks if the rule is a return without any condition
    pub fn is_unconditional_return(&self) -> bool {
        if let Some(ref act) = self.action {
            // Action is return and there are no meaningful parameters
            return *act == Action::Return && !self.has_meaningful_params();
        }
        false
    }

    /// Returns true if this action causes the packet to stop traversing the
    /// current chain
    pub fn is_final_action(&self) -> bool {
        if let Some(ref act) = self.action {
            return match act {
                Action::Log
                | Action::Passthrough
                | Action::AddSrcToAddressList
                // jump is not final because flow can return there
                | Action::Jump      
                | Action::AddDstToAddressList => false,
                _ => true,
            };
        }
        false
    }

    /// Checks if the rule has any meaningful parameters, i.e. other than comments
    pub fn has_meaningful_params(&self) -> bool {
        self.params
            .iter()
            .any(|x| {
                match x {
                    Parameter::NoValue(_) => true,
                    Parameter::Value(name, _) => {
                        match name.as_str() {
                            "comment"| "chain" => false,
                            _ => true,
                        }
                    }
                }
            })
    }
}

impl FromStr for Rule {
    type Err = anyhow::Error;

    /// Builds a [Rule] from a str
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let tokens = tokenize_rule_line(s)?;
        Rule::from_tokens(&tokens)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Accept,
    Drop,
    Log,
    Return,
    AddDstToAddressList,
    FastTrackConnection,
    Passthrough,
    Tarpit,
    AddSrcToAddressList,
    Jump,
    Reject,
}

impl Action {
    pub fn as_str(&self) -> &'static str {
        match &self {
            Action::Accept => "accept",
            Action::Drop => "drop",
            Action::Log => "log",
            Action::Return => "return",
            Action::AddDstToAddressList => "add-dst-to-address-list",
            Action::FastTrackConnection => "fasttrack-connection",
            Action::Passthrough => "passthrough",
            Action::Tarpit => "tarpit",
            Action::AddSrcToAddressList => "add-src-to-address-list",
            Action::Jump => "jump",
            Action::Reject => "reject",
        }
    }
}

impl FromStr for Action {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "accept" => Ok(Action::Accept),
            "drop" => Ok(Action::Drop),
            "log" => Ok(Action::Log),
            "return" => Ok(Action::Return),
            "add-dst-to-address-list" => Ok(Action::AddDstToAddressList),
            "fasttrack-connection" => Ok(Action::FastTrackConnection),
            "passthrough" => Ok(Action::Passthrough),
            "tarpit" => Ok(Action::Tarpit),
            "add-src-to-address-list" => Ok(Action::AddSrcToAddressList),
            "jump" => Ok(Action::Jump),
            "reject" => Ok(Action::Reject),
            _ => Err(anyhow!("unexpected action: {}", s)),
        }
    }
}

pub type Zones = HashSet<String>;

#[derive(Debug)]
pub struct Firewall {
    pub(crate) zones: Zones,
    pub(crate) policies: Policies,
    pub(crate) tables: Tables,
}

impl Firewall {
    /// Create a firewall from the specified path (reads and processes files stored there)

    pub fn dump(&self) {
        debug!(target: "fw-dump",
            "{} zones, {} tables",
            self.zones.len(),
            self.tables.len()
        );

        debug!(target: "fw-dump", "zones: {:?}", &self.zones);

        // Dump each table

        for (k, v) in self.tables.iter() {
            debug!(target: "fw-dump", "[table {}]", &k);

            // Iterate the chains in the table
            for (chain, chain_rules) in v.chains.iter() {
                // Iterate the rules in the chain
                for rule in chain_rules.rules.iter() {
                    debug!(target: "fw-dump", "[chain {}] : {}", &chain, &rule);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use assert2::check;

    use super::{Action, Chain, Parameter, Rule};
    use crate::firewall::parser;
    use crate::firewall::testing::log_rule;
    use rstest::rstest;
    use std::str::FromStr;

    #[test]
    fn test_rules() {
        // Invalid: Jump rule with no target
        let rule = Rule::from_str("action=jump").unwrap();

        println!("rule: {:?}", &rule);

        check!(rule.action.is_some());
        check!(!rule.is_valid());
        check!(!rule.is_final_action());        

        // Invalid: A rule with no action
        let rule = Rule::from_str("in-interface-list=LAN").unwrap();

        check!(rule.action.is_none());
        check!(!rule.is_valid());
        check!(format!("{}", rule) == "action=n/a in-interface-list=LAN");
        check!(!rule.is_jump());
        check!(!rule.is_final_action());

        // Invalid: A rule with an unknown action
        check!(Rule::from_str("action=unknown-action in-interface-list=LAN").is_err());

        // Valid: A log rule
        let res = parser::tokenize_rule_line("action=log disabled=yes").unwrap();
        let rule = Rule::from_tokens(&res).unwrap();

        check!(rule.is_valid());
        check!(rule.is_disabled());
        check!(!rule.is_final_action());
        check!(!rule.is_jump());
        check!(!rule.is_unconditional_return());
        check!(rule.action == Some(Action::Log));

        let rule =
            Rule::from_str("action=jump jump-target=input-CHAIN foo=bar fuu=baz keya").unwrap();

        check!(rule.is_valid());
        check!(!rule.is_disabled());
        check!(rule.action == Some(Action::Jump));
        check!(!rule.is_unconditional_return());
        check!(rule.is_jump());
        check!(rule.jump_target == Some("input-CHAIN".to_string()));

        check!(
            rule.params
                == vec![
                    Parameter::Value("foo".to_string(), "bar".to_string()),
                    Parameter::Value("fuu".to_string(), "baz".to_string()),
                    Parameter::NoValue("keya".to_string()),
                ]
        );

        // Test Display for Rule
        let res =
            parser::tokenize_rule_line("action=jump jump-target=foo disabled=yes foo").unwrap();
        let rule = Rule::from_tokens(&res).unwrap();

        check!(format!("{}", rule) == "action=jump jump-target=foo disabled=yes foo");

        // FIXME: should a rule without an action be allowed?

        // Check unconditional return
        let rule = Rule::from_str("action=return comment=foobar").unwrap();

        check!(rule.action == Some(Action::Return));
        check!(rule.is_unconditional_return());
        check!(rule.is_final_action());
    }

    #[rstest]
    fn test_chain(log_rule: Rule) {
        // test chain construction
        let mut ch = Chain::new("foo");
        check!(ch.name == "foo");
        check!(ch.len() == 0);
        check!(ch.has_unconditional_return == false);
        check!(ch.is_final == false);
        check!(ch.is_empty());

        ch.add_rule(log_rule.clone());

        check!(!ch.is_empty());
        check!(ch.len() == 1);

        check!(ch.rules[0] == log_rule);
    }

    #[rstest]
    #[case("accept", Some(Action::Accept))]
    #[case("drop", Some(Action::Drop))]
    #[case("log", Some(Action::Log))]
    #[case("return", Some(Action::Return))]
    #[case("add-dst-to-address-list", Some(Action::AddDstToAddressList))]
    #[case("fasttrack-connection", Some(Action::FastTrackConnection))]
    #[case("passthrough", Some(Action::Passthrough))]
    #[case("tarpit", Some(Action::Tarpit))]
    #[case("add-src-to-address-list", Some(Action::AddSrcToAddressList))]
    #[case("jump", Some(Action::Jump))]
    #[case("reject", Some(Action::Reject))]
    #[case("unknown", None)]
    fn test_action(#[case] name: &str, #[case] value: Option<Action>) {
        if value.is_some() {
            let v = value.unwrap();
            check!(Action::from_str(name).unwrap() == v);
            check!(v.as_str() == name);
        } else {
            // an error case
            check!(Action::from_str(name).is_err());
        }
    }
}
