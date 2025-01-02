use std::collections::HashSet;

use super::rules::Rule;
use super::utils::valid_name;
use anyhow::{anyhow, Result};
use tracing::debug;

/// Firewall chain. Contains one or multiple rules
#[derive(Clone, Debug)]
pub(crate) struct Chain {
    pub rules: Vec<Rule>,
    pub name: String,

    /// Indicates that this chain does not return
    isfinal: bool,

    /// First chain operation is an unconditional return
    ret_uncond: bool,
}

impl Chain {
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    // FIXME: are these methods needed?

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn returns_unconditionally(&self) -> bool {
        self.ret_uncond
    }

    pub fn is_final(&self) -> bool {
        self.isfinal
    }

    /// Returns an optimized version of the chain, by removing unreachable rules
    ///
    /// Arguments:
    ///
    /// * `final_chains`: names of the chains which don't return control to the caller (final chains)
    pub fn optimize(self, final_chains: Option<&HashSet<String>>) -> Self {
        let mut new_chain = ChainBuilder::new().name(&self.name).unwrap();

        // Traverse the chain and, if there's a final rule (i.e. one that accepts/drops/rejects/etc.
        // the packet) then truncate the chain at that point

        let mut iter_rules = self.rules.iter().peekable();

        while let Some(rule) = iter_rules.next() {
            // FIXME: remove disabled rules?
            // skip disabled rules
            if rule.is_disabled() {
                continue;
            }

            new_chain = new_chain.rule(rule.clone());

            // All the following optimizations happen if the current rule is unconditional,
            // i.e. it doesn't have any meaningful parameters which can condition its evaluation
            if rule.has_conditions() {
                continue;
            }

            // If the chain unconditionally returns at this point, it can be truncated
            // here, removing all following rules
            if rule.is_return() {
                debug!(target: "optimize-chain", "detected unconditional return in chain '{}'", 
                &self.name);
                //new_chain.has_unconditional_return = true;
                break;
            }

            // If a rule is final (i.e. accepts/rejects/etc. the traffic) and the action is not
            // conditioned by any parameters, then stop building the chain with the rest of the rules.
            if rule.is_final() {
                if !iter_rules.peek().is_none() {
                    // Issue this message only if the point at which the chain is
                    // truncated is not the end of the chain (where it's not really an
                    // optimization)
                    debug!(target: "optimize-chain",
                        "truncating chain '{}' because of unconditional action rule: {:?}",
                        &self.name,
                        &rule
                    );
                }
                break;
            }

            if let Some(ref fc) = final_chains {
                let target = rule.jump_target.as_ref().unwrap();
                if rule.is_jump() && fc.contains(target) {
                    // If a rule jumps to a final chain (one that doesn't return), then everything following
                    // the rule can be removed

                    debug!(target: "optimize-chain", "detected jump from '{}' to final chain '{}'",
                    &self.name, 
                    &target);
                    break;
                }
            }
        }

        new_chain.build().unwrap()
    }

    pub fn serialize(&self) -> Result<Vec<String>> {
        let mut res: Vec<String> = Vec::with_capacity(self.len());

        for rule in self.rules.iter() {
            // Prepend the chain name to the serialized rule
            res.push(format!("chain={} {}", &self.name, rule.serialize()?));
        }

        Ok(res)
    }
}

#[derive(Clone)]
pub struct ChainBuilder {
    pub rules: Vec<Rule>,
    chain_name: Option<String>,
    is_final: bool,
    returns_unconditionally: bool,
    has_meaningful_rules: bool,
}

impl ChainBuilder {
    pub fn new() -> Self {
        ChainBuilder {
            rules: vec![],
            chain_name: None,
            is_final: false,
            returns_unconditionally: false,
            has_meaningful_rules: false,
        }
    }

    pub fn name(self, name: &str) -> Result<Self> {
        if !valid_name(name) {
            return Err(anyhow!("invalid chain name '{}'", name));
        }
        Ok(ChainBuilder {
            chain_name: Some(name.to_string()),
            ..self
        })
    }

    pub fn rule(&self, rule: Rule) -> Self {
        let mut cb = self.clone();

        if !rule.is_disabled() {
            // If the currently added rule takes a final action, then the chain becomes "final",
            // meaning the evaluation flow of the packet will not return after traversing this
            // chain
            if rule.is_final() {
                cb.is_final = true
            }

            // Detect if the chain has an unconditional return. This means that the first
            // meaningful rule is a return
            if rule.is_return() && !rule.has_conditions() && !cb.has_meaningful_rules {
                cb.returns_unconditionally = true;
            }

            // If this rule has conditions, then mark the whole chain as having (at least) a 
            // meaningful rule
            if rule.has_conditions() {
                cb.has_meaningful_rules = true;
            }
        }

        cb.rules.push(rule);

        cb
    }

    pub fn build(self) -> Result<Chain> {
        if self.chain_name.is_none() {
            return Err(anyhow!("chain name is not set"));
        }

        Ok(Chain {
            name: self.chain_name.unwrap(),
            rules: self.rules,
            isfinal: self.is_final,
            ret_uncond: self.returns_unconditionally,
        })
    }
}

#[cfg(test)]
mod tests {

    use crate::firewall::actions::Action;
    use crate::firewall::testing::log_rule;
    use crate::firewall::{chains::ChainBuilder, rules::Rule, rules::RuleBuilder};
    use anyhow::Result;
    use assert2::check;
    use rstest::rstest;


    #[rstest]
    fn test_chain_creation(log_rule: Rule) -> Result<()> {

        let res = ChainBuilder::new().build();
        check!(res.is_err());

        let ch = ChainBuilder::new().name("foo").unwrap().build().unwrap();
        check!(ch.name == "foo");
        check!(ch.len() == 0);
        check!(ch.returns_unconditionally() == false);
        check!(ch.is_final() == false);
        check!(ch.is_empty());

        let ch = ChainBuilder::new()
            .name("foo")?
            .rule(log_rule.clone())
            .build()?;

        check!(!ch.is_empty());
        check!(ch.len() == 1);

        check!(ch.rules[0] == log_rule);

        Ok(())
    }

    #[rstest]
    fn test_optimize_disabled_rule() -> Result<()> {
        // FIXME: think if it's really wise to optimize out disabled rules. Might not be.

        // Test that a disabled rule is optimized out
        let ch = ChainBuilder::new()
            .name("test")?
            .rule(RuleBuilder::from_str("action=log disabled=yes")?.build()?)
            .rule(RuleBuilder::from_str("action=drop")?.build()?)
            .build()?;
        check!(ch.len() == 2);

        let ch = ch.optimize(None);

        check!(ch.len() == 1);

        // What's left is the drop rule
        let action = ch.rules[0].action.as_ref().unwrap();
        check!(*action == Action::Drop);

        Ok(())
    }

    #[rstest]
    fn test_optimize_unconditional_return() -> Result<()> {
        // A conditional return (proto=tcp) doesn't get optimized out
        let ch = ChainBuilder::new()
            .name("test")?
            .rule(
                RuleBuilder::from_str("action=return protocol=tcp")?
                    .build()?,
            )
            .rule(
                // FIXME: from_str() should return the rule directly without build()ing it?
                RuleBuilder::from_str("action=drop")?.build()?,
            )
            .build()?;
        check!(ch.len() == 2);

        // FIXME: add test for optimizing chain with final_chains
        let ch = ch.optimize(None);
        check!(ch.len() == 2);

        // Am unconditional return rule discards everything following it
        let ch = ChainBuilder::new()
            .name("test")?
            .rule(RuleBuilder::from_str("action=return")?.build()?)
            .rule(RuleBuilder::from_str("action=drop")?.build()?)
            .build()?;
        check!(ch.len() == 2);

        let ch = ch.optimize(None);
        check!(ch.len() == 1);

        // What's left is the return rule
        let action = ch.rules[0].action.as_ref().unwrap();
        check!(*action == Action::Return);

        Ok(())
    }

    #[rstest]
    fn test_optimize_unconditional_action() -> Result<()> {
        // A conditional accept (proto=tcp) doesn't get optimized out
        let ch = ChainBuilder::new()
            .name("test")?
            .rule(RuleBuilder::from_str("action=accept protocol=tcp")?.build()?)
            .rule(RuleBuilder::from_str("action=drop")?.build()?)
            .build()?;
        check!(ch.len() == 2);

        let ch = ch.optimize(None);
        check!(ch.len() == 2);

        // Am unconditional accept rule discards everything following it
        let ch = ChainBuilder::new()
            .name("test")?
            .rule(RuleBuilder::from_str("action=accept")?.build()?)
            .rule(RuleBuilder::from_str("action=drop")?.build()?)
            .build()?;
        check!(ch.len() == 2);

        let ch = ch.optimize(None);
        check!(ch.len() == 1);

        // What's left is the accept rule
        let action = ch.rules[0].action.as_ref().unwrap();
        check!(*action == Action::Accept);

        Ok(())
    }
}
