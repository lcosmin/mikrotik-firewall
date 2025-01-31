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

    /// Indicates that this chain does not return (it has a 'final' action, e.g. accept, drop)
    isfinal: bool,
}

impl Chain {
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_final(&self) -> bool {
        self.isfinal
    }

    /// Returns an optimized version of the chain, by removing unreachable rules
    ///
    /// Arguments:
    ///
    /// * `final_chains`: names of the chains which don't return control to the caller (final chains)
    /// * `removed_chains`: names of the chains which were removed
    pub fn optimize(
        self,
        final_chains: Option<&HashSet<String>>,
        removed_chains: Option<&HashSet<String>>,
    ) -> Self {
        let log_target = format!("[chain {}]", &self.name);

        let mut new_chain = ChainBuilder::new().name(&self.name).unwrap();

        // Traverse the chain and, if there's a final rule (i.e. one that accepts/drops/rejects/etc.
        // the packet) then truncate the chain at that point

        let mut iter_rules = self.rules.iter().peekable();

        while let Some(rule) = iter_rules.next() {
            let is_last_rule = iter_rules.peek().is_none();

            // skip disabled rules
            if rule.is_disabled() {
                // TODO: don't remove disabled rules?
                debug!(target: "optimize-chain",
                "{} removing disabled rule: {}", &log_target, rule);
                continue;
            }

            // If the chain unconditionally returns at this point it can be truncated here,
            // removing all following rules
            if rule.is_return() && !rule.has_matchers() {
                if rule.has_side_effects() {
                    // if the rule has logging side effects, keep it in the resulting chain
                    new_chain = new_chain.rule(rule.clone());
                } else if !is_last_rule {
                    // FIXME: improve logging, maybe log all removed rules following the point of truncation?
                    debug!(target: "optimize-chain", "{} truncating chain because of unconditional return rule: {}",
                    &log_target, rule);
                }
                break;
            }

            // If the rule is a jump and it jumps to a chain that will be removed (i.e. it's empty),
            // then don't add the jump rule
            if rule.is_jump() {
                if let Some(ref to_remove) = removed_chains {
                    let target = rule.jump_target.as_ref().unwrap();
                    if to_remove.contains(target) {
                        debug!(target: "optimize-chain", "{} skipping jump rule to removed chain '{}'",
                        &log_target,
                        &target);
                        continue;
                    }
                }
            }

            new_chain = new_chain.rule(rule.clone());

            // All the following optimizations happen if the current rule doesn't have
            // any matchers
            if rule.has_matchers() {
                continue;
            }

            // If a rule is final (i.e. accepts/rejects/etc. the traffic) and it doesn't
            // have matchers, then stop adding any following rules.
            if rule.is_final() {
                if !iter_rules.peek().is_none() {
                    // Issue this message only if the point at which the chain is
                    // truncated is not the end of the chain (where it's not really an
                    // optimization)
                    debug!(target: "optimize-chain",
                        "{} truncating chain because of final rule: {}",
                        &log_target,
                        rule
                    );
                }
                break;
            }

            if let Some(ref fc) = final_chains {
                if rule.is_jump() {
                    let target = rule.jump_target.as_ref().unwrap();
                    if fc.contains(target) {
                        // If a rule jumps to a final chain (one that doesn't return), then everything following
                        // the rule can be removed
                        debug!(target: "optimize-chain",
                        "{} detected jump to final chain '{}': {}", &log_target, &target, rule);
                        break;
                    }
                }
            }
        }

        // FIXME: test complex chain jumps, 2+ levels deep, which might be affected by optimizations
        //  Might need to repeat optimization loop multiple times (add flag indicating changes and run
        //  until no changes made anymore)?

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
    chain: Option<String>,
    is_final: bool,
    has_meaningful_rules: bool,
}

impl ChainBuilder {
    pub fn new() -> Self {
        ChainBuilder {
            rules: vec![],
            chain: None,
            is_final: false,
            has_meaningful_rules: false,
        }
    }

    pub fn name(self, name: &str) -> Result<Self> {
        if !valid_name(name) {
            return Err(anyhow!("invalid chain name '{}'", name));
        }
        Ok(ChainBuilder {
            chain: Some(name.to_string()),
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

            // If this rule has matcher(s), then mark the whole chain as having (at least) a
            // meaningful rule
            if rule.has_matchers() {
                cb.has_meaningful_rules = true;
            }
        }

        cb.rules.push(rule);

        cb
    }

    pub fn build(self) -> Result<Chain> {
        if self.chain.is_none() {
            return Err(anyhow!("chain name is not set"));
        }

        Ok(Chain {
            name: self.chain.unwrap(),
            rules: self.rules,
            isfinal: self.is_final,
        })
    }
}

#[cfg(test)]
mod tests {

    use std::collections::HashSet;

    use crate::firewall::actions::Action;
    use crate::firewall::testing::log_rule;
    use crate::firewall::{chains::ChainBuilder, rules::Rule, rules::RuleBuilder};
    use anyhow::Result;
    use assert2::check;
    use rstest::rstest;

    /*

    Optimization scenarios:

    1) optimize out rules with no action
    2) optimize chain by truncating at unconditional return point
    3) optimize chain by truncating when jumping to a final chain
    4) optimize chain by removing rules which jump to empty chains

    */

    #[test]
    fn test_truncation_of_chain_at_final_action() -> Result<()> {
        let chain = ChainBuilder::new()
            .name("test")?
            .rule(RuleBuilder::from_str("action=accept protocol=tcp")?.build()?)
            .rule(RuleBuilder::from_str("action=drop")?.build()?)
            .rule(RuleBuilder::from_str("action=reject protocol=udp")?.build()?)
            .build()?;

        let chain = chain.optimize(None, None);

        check!(chain.is_final());
        check!(chain.len() == 2);
        check!(chain.rules[0].action == Action::Accept);
        check!(chain.rules[1].action == Action::Drop);

        Ok(())
    }

    #[test]
    fn test_truncation_of_chain_when_jumping_to_final_chain() -> Result<()> {
        let chain = ChainBuilder::new()
            .name("test")?
            .rule(RuleBuilder::from_str("action=jump jump-target=not-final-chain")?.build()?)
            .rule(RuleBuilder::from_str("action=passthrough log=yes")?.build()?)
            .rule(RuleBuilder::from_str("action=jump jump-target=final-chain")?.build()?)
            .rule(RuleBuilder::from_str("action=log")?.build()?)
            .build()?;

        let mut final_chains = HashSet::new();

        final_chains.insert("final-chain".to_string());

        check!(!chain.is_final());

        let chain = chain.optimize(Some(&final_chains), None);

        check!(!chain.is_final());

        check!(chain.len() == 3);
        check!(chain.rules[0].action == Action::Jump);
        check!(chain.rules[1].action == Action::Passthrough);
        check!(chain.rules[2].action == Action::Jump);
        // The final log rule was removed

        Ok(())
    }

    #[test]
    fn test_truncation_of_chain_at_unconditional_return() -> Result<()> {
        // Test case: the chain gets truncated at the point of action=return; because the
        // rule doesn't have side effects, it will be removed also
        let chain = ChainBuilder::new()
            .name("test")?
            .rule(RuleBuilder::from_str("action=passthrough log=yes protocol=tcp")?.build()?)
            .rule(RuleBuilder::from_str("action=return")?.build()?)
            .rule(RuleBuilder::from_str("action=drop")?.build()?)
            .build()?;

        // FIXME: optimize differently, not by return unconditionally, but by calling empty
        // chains and truncating at the return point
        check!(chain.is_final());
        check!(chain.len() == 3);

        let chain = chain.optimize(None, None);

        check!(!chain.is_final());
        check!(chain.len() == 1);
        check!(chain.rules[0].action == Action::Passthrough); // Confirm that only the passthrough rule remains

        // Test case: the chain gets truncated at the point of action=return; because the
        // rule has side effects, it won't be removed
        let chain = ChainBuilder::new()
            .name("test")?
            .rule(RuleBuilder::from_str("action=passthrough log=yes protocol=tcp")?.build()?)
            .rule(RuleBuilder::from_str("action=return log=yes")?.build()?)
            .rule(RuleBuilder::from_str("action=drop")?.build()?)
            .build()?;

        let chain = chain.optimize(None, None);

        check!(chain.len() == 2);
        check!(chain.rules[0].action == Action::Passthrough);
        check!(chain.rules[1].action == Action::Return);

        // Test case: chain that starts with an unconditional return gets optimized
        // to empty

        let chain = ChainBuilder::new()
            .name("test")?
            .rule(RuleBuilder::from_str("action=return")?.build()?)
            .rule(RuleBuilder::from_str("action=drop")?.build()?)
            .build()?;

        check!(chain.len() == 2);

        let chain = chain.optimize(None, None);

        check!(chain.len() == 0);
        check!(chain.is_empty());

        Ok(())
    }

    #[test]
    fn test_optimization_of_jumps_to_removed_chains() -> Result<()> {
        let chain = ChainBuilder::new()
            .name("test")?
            .rule(RuleBuilder::from_str("action=jump jump-target=not-empty-chain")?.build()?)
            .rule(RuleBuilder::from_str("action=jump jump-target=empty-chain-1")?.build()?)
            .rule(RuleBuilder::from_str("action=log")?.build()?)
            .rule(RuleBuilder::from_str("action=jump jump-target=empty-chain-2")?.build()?)
            .build()?;

        let mut removed_chains = HashSet::new();

        removed_chains.insert("empty-chain-1".to_string());
        removed_chains.insert("empty-chain-2".to_string());

        let chain = chain.optimize(None, Some(&removed_chains));

        check!(!chain.is_final());
        check!(chain.len() == 2);
        check!(chain.rules[0].action == Action::Jump);
        check!(*chain.rules[0].jump_target.as_ref().unwrap() == "not-empty-chain");
        check!(chain.rules[1].action == Action::Log);

        Ok(())
    }

    #[rstest]
    fn test_chain_creation(log_rule: Rule) -> Result<()> {
        let res = ChainBuilder::new().build();
        check!(res.is_err());

        let ch = ChainBuilder::new().name("foo").unwrap().build().unwrap();
        check!(ch.name == "foo");
        check!(ch.len() == 0);
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

    #[test]
    fn test_optimize_disabled_rule() -> Result<()> {
        // FIXME: think if it's really wise to optimize out disabled rules. Might not be.

        // Test that a disabled rule is optimized out
        let ch = ChainBuilder::new()
            .name("test")?
            .rule(RuleBuilder::from_str("action=log disabled=yes")?.build()?)
            .rule(RuleBuilder::from_str("action=drop")?.build()?)
            .build()?;
        check!(ch.len() == 2);

        let ch = ch.optimize(None, None);

        check!(ch.len() == 1);
        // What's left is the drop rule
        check!(ch.rules[0].action == Action::Drop);

        Ok(())
    }

    #[test]
    fn test_serialize() -> Result<()> {
        let chain = ChainBuilder::new().name("test-chain")?.build()?;

        let result = chain.serialize()?;

        check!(result.len() == 0);

        let chain = ChainBuilder::new()
            .name("test-chain")?
            .rule(RuleBuilder::from_str("action=accept log=yes protocol=tcp")?.build()?)
            .build()?;

        let result = chain.serialize()?;
        check!(result.len() == 1);
        check!(result[0].as_str() == "chain=test-chain action=accept log=yes protocol=tcp");

        Ok(())
    }
}
