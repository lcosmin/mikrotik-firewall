use super::utils::escape;
use crate::firewall::actions::Action;
use crate::firewall::parser::{tokenize_rule_line, Token};
use std::fmt;
use std::str::FromStr;

use anyhow::{anyhow, Result};

/// A parameter for a [Rule]
#[derive(Clone, Debug, PartialEq)]
pub enum Parameter {
    NoValue(String),            // FIXME: is this possible in the firewall part ?
    Value(String, String),
}

/// Firewall rule
#[derive(Clone, Debug, PartialEq)]
pub struct Rule {
    pub action: Option<Action>,
    pub jump_target: Option<String>,
    pub disabled: Option<bool>,
    pub params: Vec<Parameter>, // TODO: should be a map to avoid duplicates; also for fast searching

    _has_meaningful_params: bool,
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
        if let Some(ref act) = self.action {
            if *act == Action::Jump {
                return true;
            }
        }
        false
    }

    /// Checks if the rule is a return without any condition
    pub fn is_return(&self) -> bool {
        if let Some(ref act) = self.action {
            // Action is return and there are no meaningful parameters
            return *act == Action::Return;
        }
        false
    }

    /// Returns true if this action causes the packet to stop traversing the
    /// current chain
    pub fn is_final(&self) -> bool {
        if self.has_conditions() {
            return false;
        }

        if let Some(ref act) = self.action {
            return match act {
                Action::Log
                | Action::AddDstToAddressList 
                | Action::AddSrcToAddressList
                | Action::Passthrough
                // jump is not final because flow can return
                | Action::Jump => false,
                _ => {
                    true
                }
            };
        }
        false
    }

    /// Checks if the rule has any meaningful parameters which can condition when a rule
    /// is applied. At the moment, only chain and comment are considered meaningless parameters.
    // TODO: improve meaningless parameters
    pub fn has_conditions(&self) -> bool {
        return self._has_meaningful_params;
    }

    pub fn serialize(&self) -> Result<String> {
        // preallocate a maximum possible size for the result vector
        let mut result: Vec<String> = Vec::with_capacity(self.params.len() + 2);

        // Write the action
        if let Some(ref action) = self.action {
            result.push(format!("action={}", action.as_str()));
        }

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
    _has_conditions: bool,
}

impl RuleBuilder {
    /// Creates a new [RuleBuilder]
    pub fn new() -> Self {
        RuleBuilder {
            params: vec![],
            _has_conditions: false,
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

        // TODO: add validation for parameters, i.e. know which can appear standalone and which
        // has a value

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

        // Determine if this is a meaningful parameter; this is a parameter which
        // can alter the evaluation of the rule by conditioning it, e.g. accept
        // a packet when the destination port is 123 vs accept a packet.
        let has_conditions = self._has_conditions
            || match &p {
                Parameter::NoValue(_) => true,
                Parameter::Value(name, _) => match name.as_str() {
                    // known parameters which don't influence the rule evaluation
                    "comment" | "chain" | "action" | "jump-target" => false,
                    _ => true,
                },
            };

        params.push(p);

        Self {
            params: params,
            _has_conditions: has_conditions,
        }
    }

    pub fn build(&self) -> Result<Rule> {
        let mut rule = Rule {
            action: None,
            params: vec![],
            jump_target: None,
            disabled: None,
            _has_meaningful_params: self._has_conditions,
        };

        for p in self.params.iter() {
            match p {
                Parameter::NoValue(_) => rule.params.push(p.clone()),
                Parameter::Value(key, value) => match key.as_str() {
                    "action" => {
                        let act = Action::from_str(value)?;
                        match rule.action {
                            None => rule.action = Some(act),
                            Some(_) => return Err(anyhow!("duplicate action in rule")),
                        }
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
        match rule.action {
            None =>
            // There can be rules with no actions, e.g. "chain=input comment=hello"
            { /*return Err(anyhow!("rule has no action"))*/ }
            Some(ref act) => {
                // Sanity check: action is jump && have jump target
                if *act == Action::Jump && rule.jump_target.is_none() {
                    return Err(anyhow!("rule is jump but has no jump target"));
                }
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

        check!(rule.action.is_none());

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

        check!(rule.has_conditions());
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
}
