use super::utils::escape;
use crate::firewall::actions::Action;
use crate::firewall::parser::{tokenize_rule_line, Token};
use serde::Serialize;
use std::fmt;
use std::str::FromStr;

use anyhow::{anyhow, Result};

/// A parameter for a [Rule]
#[derive(Clone, Debug, PartialEq, Serialize)]
pub enum Parameter {
    NoValue(String), // FIXME: is it possible to have no value parameters for firewall commands?
    Value(String, String),
}

/// Firewall rule
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Rule {
    pub action: Action,
    pub jump_target: Option<String>,
    pub disabled: Option<bool>,
    pub params: Vec<Parameter>, // TODO: should be a map to avoid duplicates; also for fast searching

    _has_matchers: bool, // Rule has matcher conditions (e.g. match on a specific TCP port)
    _has_side_effects: bool, // Rule has some sort of logging side effect (i.e. log=yes)
    _has_action: bool,   // for detecting duplicate action= in rules
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.serialize().map_err(|_| fmt::Error)?)
    }
}

impl Rule {
    /// Returns true if the rule is disabled
    pub fn is_disabled(&self) -> bool {
        self.disabled.unwrap_or(false)
    }

    /// Checks if this rule is a jump rule
    pub fn is_jump(&self) -> bool {
        self.action == Action::Jump
    }

    /// Returns true if the rule has an Action::Return
    pub fn is_return(&self) -> bool {
        self.action == Action::Return
    }

    /// Returns true if this action causes the packet to stop traversing the
    /// current chain
    pub fn is_final(&self) -> bool {
        if self.has_matchers() {
            return false;
        }

        match self.action {
                Action::Log
                | Action::AddDstToAddressList
                | Action::AddSrcToAddressList
                | Action::Passthrough
                // jump is not final because flow can return
                | Action::Jump => false,
                _ => {
                    true
                }
        }
    }

    /// Checks if the rule has any conditions which can condition when a rule
    /// is applied.
    pub fn has_matchers(&self) -> bool {
        self._has_matchers
    }

    pub fn has_side_effects(&self) -> bool {
        self._has_side_effects
    }
    pub fn serialize(&self) -> Result<String> {
        // preallocate a maximum possible size for the result vector
        let mut result: Vec<String> = Vec::with_capacity(self.params.len() + 2);

        // Write the action
        result.push(format!("action={}", self.action.as_str()));

        // Write the jump-target, if any
        if let Some(ref jump_target) = self.jump_target {
            result.push(format!("jump-target={}", jump_target));
        }

        // Write the disabled flag, if any
        match self.disabled {
            None | Some(false) => {}
            Some(true) => result.push("disabled=yes".to_string()),
        }

        for arg in self.params.iter() {
            match arg {
                Parameter::NoValue(name) => result.push(name.clone()),
                Parameter::Value(name, value) => {
                    let escaped_value = escape(value);

                    result.push(format!("{}={}", &name, &escaped_value));
                }
            }
        }

        Ok(result.join(" "))
    }
}

/// A builder for `Rule` objects
pub struct RuleBuilder {
    params: Vec<Parameter>,
    _has_matchers: bool,
    _has_side_effects: bool,
}

impl RuleBuilder {
    /// Creates a new [RuleBuilder]
    pub fn new() -> Self {
        RuleBuilder {
            params: vec![],
            _has_matchers: false,
            _has_side_effects: false,
        }
    }

    /// Creates a [RuleBuilder] using the given rule as starting point.
    /// Returns error if the given rule is invalid
    pub fn from_str(s: &str) -> Result<Self> {
        let tokens = tokenize_rule_line(s)?;

        // ...compile the rule
        RuleBuilder::from_tokens(&tokens)
    }

    /// Creates a [RuleBuilder] from a parsed vector of [Token]s
    /// Returns an error if the given token vector is invalid
    pub fn from_tokens<'a>(v: &Vec<Token<'a>>) -> Result<Self> {
        let mut rule_builder = RuleBuilder::new();

        for tok in v.iter() {
            match tok {
                Token::Key(k) => {
                    rule_builder = rule_builder.parameter(Parameter::NoValue(k.to_string()))
                }
                Token::KeyValue(k, v) => {
                    rule_builder =
                        rule_builder.parameter(Parameter::Value(k.to_string(), v.to_string()))
                }
            }
        }

        Ok(rule_builder)
    }

    pub fn parameter(self, p: Parameter) -> Self {
        let mut params = self.params;
        let mut has_matchers = self._has_matchers;
        let mut has_side_effects = self._has_side_effects;

        match &p {
            Parameter::NoValue(_) => {
                has_matchers |= true;
            }
            Parameter::Value(name, value) => {
                match name.as_str() {
                    "comment" | "chain" | "action" | "jump-target" => {
                        // these don't count as matchers nor side effects
                    }
                    "log" => {
                        has_side_effects |= value.as_str() == "yes";
                    }
                    _ => {
                        has_matchers |= true;
                    }
                }
            }
        }

        params.push(p);

        Self {
            params: params,
            _has_matchers: has_matchers,
            _has_side_effects: has_side_effects,
        }
    }

    pub fn build(&self) -> Result<Rule> {
        let mut rule = Rule {
            action: Action::Accept,
            params: vec![],
            jump_target: None,
            disabled: None,
            _has_matchers: self._has_matchers,
            _has_side_effects: self._has_side_effects,
            _has_action: false,
        };

        for p in self.params.iter() {
            match p {
                Parameter::NoValue(_) => rule.params.push(p.clone()),
                Parameter::Value(key, value) => match key.as_str() {
                    "action" => {
                        let act = Action::from_str(value)?;

                        if rule._has_action {
                            return Err(anyhow!("duplicate action in rule"));
                        }

                        rule._has_action = true;
                        rule.action = act;
                    }
                    "jump-target" => match rule.jump_target {
                        // FIXME: validate value
                        None => rule.jump_target = Some(value.clone()),
                        Some(_) => return Err(anyhow!("duplicate jump-target in rule")),
                    },
                    "disabled" => rule.disabled = Some(value == "yes"),
                    _ => {
                        rule.params.push(p.clone());
                    }
                },
            }
        }

        // Sanity check: have action
        if !rule._has_action {
            rule.action = Action::Accept;
        } else {
            // Sanity check: action is jump && have jump target
            if rule.action == Action::Jump && rule.jump_target.is_none() {
                return Err(anyhow!("rule is jump but has no jump target"));
            }
        }

        Ok(rule)
    }
}

#[cfg(test)]
mod tests {

    use super::RuleBuilder;
    use crate::firewall::{actions::Action, rules::*};

    use assert2::check;
    use rstest::rstest;

    #[test]
    fn test_rule_with_no_action() -> Result<()> {
        let rule = RuleBuilder::from_str("in-interface-list=LAN")?.build()?;
        check!(rule.action == Action::Accept);
        Ok(())
    }

    #[test]
    fn test_rule_with_unknown_action() -> Result<()> {
        let rule = RuleBuilder::from_str("action=unknown")?.build();

        check!(rule.is_err());

        Ok(())
    }

    #[test]
    fn test_rule_with_multiple_actions() -> Result<()> {
        let rule = RuleBuilder::from_str("action=accept action=drop")?.build();

        check!(rule.is_err());

        Ok(())
    }

    #[test]
    fn test_jump_rule_with_no_target() -> Result<()> {
        let rule = RuleBuilder::from_str("action=jump")?.build();
        check!(rule.is_err());

        Ok(())
    }

    #[test]
    fn test_jump_rule_with_two_targets() -> Result<()> {
        let rule = RuleBuilder::from_str("action=jump jump-target=foo jump-target=bar")?.build();

        check!(rule.is_err());
        Ok(())
    }

    #[test]
    fn test_rule_with_various_parameters() -> Result<()> {
        let rule = RuleBuilder::from_str("action=accept foo=ba/r fuu=ba;z keya")?.build()?;

        check!(rule.has_matchers());
        check!(
            rule.params
                == vec![
                    Parameter::Value("foo".to_string(), "ba/r".to_string()),
                    Parameter::Value("fuu".to_string(), "ba;z".to_string()),
                    Parameter::NoValue("keya".to_string()),
                ]
        );

        check!(rule.serialize()? == "action=accept foo=\"ba/r\" fuu=\"ba;z\" keya");
        Ok(())
    }

    #[test]
    fn test_display_for_rule() -> Result<()> {
        let rule =
            RuleBuilder::from_str("action=jump jump-target=foo disabled=yes foo")?.build()?;

        check!(format!("{}", rule) == "action=jump jump-target=foo disabled=yes foo");

        Ok(())
    }

    #[test]
    fn test_jump_rule() -> Result<()> {
        let rule = RuleBuilder::from_str("action=jump jump-target=input-CHAIN")?.build()?;
        check!(rule.action == Some(Action::Jump));
        check!(rule.is_jump());
        check!(rule.jump_target == Some("input-CHAIN".to_string()));

        check!(rule.serialize()? == "action=jump jump-target=input-CHAIN");

        check!(!RuleBuilder::from_str("action=accept")?.build()?.is_jump());

        Ok(())
    }

    #[test]
    fn test_return_rule() -> Result<()> {
        let rule = RuleBuilder::from_str("action=return")?.build()?;

        check!(rule.action == Some(Action::Return));
        check!(rule.is_return());

        let rule = RuleBuilder::from_str("action=accept")?.build()?;
        check!(!rule.is_return());

        Ok(())
    }

    #[test]
    fn test_disabled_rule() -> Result<()> {
        let rule = RuleBuilder::from_str("action=log disabled=yes")?.build()?;

        check!(rule.is_disabled());
        check!(rule.action == Some(Action::Log));

        check!(rule.serialize()? == "action=log disabled=yes");

        let rule = RuleBuilder::from_str("action=log")?.build()?;
        check!(!rule.is_disabled());

        Ok(())
    }

    #[rstest]
    #[case::action_accept(Action::Accept, true, false)]
    #[case::action_add_dst_to_address_list(Action::AddDstToAddressList, false, false)]
    #[case::action_add_src_to_address_list(Action::AddSrcToAddressList, false, false)]
    #[case::action_drop(Action::Drop, true, false)]
    #[case::action_fasttrack(Action::FastTrackConnection, true, false)]
    #[case::action_log(Action::Log, false, false)]
    #[case::action_passthrough(Action::Passthrough, false, false)]
    #[case::action_reject(Action::Reject, true, false)]
    #[case::action_return(Action::Return, true, false)]
    #[case::action_tarpit(Action::Tarpit, true, false)]
    #[case::action_jump(Action::Jump, false, false)]
    fn test_final_rule(
        #[case] action: Action,
        #[case] outcome_unconditional: bool,
        #[case] outcome_conditional: bool,
    ) -> Result<()> {
        let mut extra = String::new();

        if action == Action::Jump {
            extra = " jump-target=input".to_string();
        }

        // Test unconditional outcome
        let raw_rule = format!("action={} comment=hi{}", action.as_str(), extra.as_str());
        let rule = RuleBuilder::from_str(&raw_rule)?.build()?;

        check!(rule.is_final() == outcome_unconditional);

        // Test conditional outcome
        let raw_rule = format!(
            "action={} comment=hi protocol=tcp{}",
            action.as_str(),
            extra.as_str()
        );
        let rule = RuleBuilder::from_str(&raw_rule)?.build()?;

        check!(rule.is_final() == outcome_conditional);

        Ok(())
    }

    #[test]
    fn test_has_matchers() -> Result<()> {
        let rule = RuleBuilder::from_str("action=accept comment=hi chain=input")?.build()?;

        check!(rule.has_matchers() == false);

        let rule =
            RuleBuilder::from_str("action=accept comment=hi chain=input log=yes")?.build()?;

        check!(rule.has_matchers() == false);

        let rule =
            RuleBuilder::from_str("action=accept comment=hi chain=input protocol=tcp")?.build()?;

        check!(rule.has_matchers() == true);

        Ok(())
    }

    #[test]
    fn test_has_side_effects() -> Result<()> {
        let rule = RuleBuilder::from_str("action=accept comment=hi chain=input")?.build()?;
        check!(rule.has_side_effects() == false);

        let rule =
            RuleBuilder::from_str("action=accept comment=hi chain=input protocol=tcp")?.build()?;
        check!(rule.has_side_effects() == false);

        let rule =
            RuleBuilder::from_str("action=accept comment=hi chain=input log=yes")?.build()?;
        check!(rule.has_side_effects() == true);

        Ok(())
    }
}
