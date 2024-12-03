use std::collections::HashSet;

use tracing::debug;

use super::structures::{Chain, Firewall, Table, Tables};

pub fn optimize(firewall: &mut Firewall) {
    let mut new_tables = Tables::new();

    // Optimize tables

    for (table_name, table) in firewall.tables.iter() {
        new_tables.insert(table_name.clone(), optimize_table(table));
    }

    firewall.tables = new_tables;
}

/// Optimizes a table by removing unnecessary chains.
fn optimize_table(input_table: &Table) -> Table {
    // TODO: optimization statistics, how many chains/rules eliminated.
    // TODO: should be called multiple times until no more changes; should return a bool if changed or not ?
    // TODO: if a chain jumps directly to another chain (first rule) and there's only this jump rule in the chain,
    //       optimize it by a direct jump to the target chain;
    // TODO: chain contains accepts with no side effects (like logging?) and then a final accept

    let mut chains_to_remove: HashSet<String> = HashSet::new();

    // Table optimization:
    //
    // - create new table
    // - optimize each chain individually
    // - mark empty chains for removal
    // - remove calls to chains that return imediately
    // - truncate chains which jump to final chains
    //

    let mut new_table = Table::new();

    //
    // Optimize chains individually and mark empty ones for removal
    //
    debug!(target: "optimize", "optimizing chains...");
    for (chain_name, chain) in input_table.chains.iter() {
        let optimized_chain = optimize_chain(chain);

        // Test for empty chains
        if optimized_chain.is_empty() {
            debug!(target: "optimize", "found empty chain '{}'", &chain_name);
            chains_to_remove.insert(chain_name.clone());
            continue;
        }

        // Test for chain that immediately returns
        if optimized_chain.has_unconditional_return && optimized_chain.len() == 1 {
            debug!(target: "optimize", "chain '{}' returns immediately", &chain_name);
            chains_to_remove.insert(chain_name.clone());
            continue;
        }

        new_table
            .chains
            .insert(chain_name.to_string(), optimized_chain);
    }

    let table = new_table;

    let mut new_table = Table::new();

    // - iterate all remaining rules and remove those referencing the removed chains
    for (chain_name, chain) in table.chains.iter() {
        let mut new_chain = Chain::new(&chain.name);

        for rule in chain.rules.iter() {
            if !rule.is_jump() {
                // not a jump rule, push it to the new chain
                new_chain.rules.push(rule.clone());
                continue;
            }

            let jump_target = rule.jump_target.as_ref().expect("get jump target");

            if chains_to_remove.contains(jump_target) {
                debug!(target: "optimize", "[chain {}] removing rule that jumps to unnecessary chain: {}", 
                    &chain_name, rule);
                continue;
            }

            new_chain.rules.push(rule.clone());
        }

        new_table.chains.insert(chain_name.to_string(), new_chain);
    }

    new_table
}

fn optimize_chain(input_chain: &Chain) -> Chain {
    let mut new_chain = Chain::new(&input_chain.name);

    // Traverse the chain and, if there's a final rule (i.e. one that accepts/drops/rejects/etc. the packet)
    // then truncate the chain at that point

    let mut iter_rules = input_chain.rules.iter().peekable();

    while let Some(rule) = iter_rules.next() {
        if rule.is_disabled() {
            continue;
        }

        // If a rule is final (i.e. accepts/rejects/etc. the traffic) and the action is not conditioned
        // by any parameters, then stop building the chain with the rest of the rules.
        new_chain.add_rule(rule.clone());

        if rule.is_unconditional_return() {
            debug!(target: "optimize-chain", "detected unconditional return in chain '{}'", &input_chain.name);
            new_chain.has_unconditional_return = true;
            break;
        }

        if rule.is_final_action() && !rule.has_meaningful_params() {
            if !iter_rules.peek().is_none() {
                // Issue this message only if the point at which the chain is
                // truncated is not the end of the chain (where it's not really an
                // optimization)
                debug!(target: "optimize-chain",
                    "truncating chain '{}' because of unconditional action rule: {:?}",
                    &input_chain.name,
                    &rule
                );
            }

            new_chain.is_final = true; // FIXME: check if this is still necessary
            break;
        }

        // TODO: detect also jump rules that jump to a chain which doesn't return. Flag in a chain to indicate
        // that it doesn't return ?
    }

    new_chain
}

#[cfg(test)]
mod tests {

    use super::optimize_chain;
    use crate::firewall::structures::{Action, Chain, Rule};
    use assert2::check;
    use rstest::rstest;
    use std::str::FromStr;

    use crate::firewall::testing::log_rule;

    #[rstest]
    fn test_optimize_disabled_rule() {
        // FIXME: think if it's really wise to optimize out disabled rules. Might not be.

        // Test that a disabled rule is optimized out
        let mut ch = Chain::new("test");

        ch.add_rule(Rule::from_str("action=log disabled=yes").unwrap());
        ch.add_rule(Rule::from_str("action=drop").unwrap());
        check!(ch.len() == 2);

        let opt_chain = optimize_chain(&ch);
        check!(opt_chain.len() == 1);

        // What's left is the drop rule
        let action = opt_chain.rules[0].action.as_ref().unwrap();
        check!(*action == Action::Drop);
    }

    #[rstest]
    fn test_optimize_unconditional_return() {
        // A conditional return (proto=tcp) doesn't get optimized out
        let mut ch = Chain::new("test");

        ch.add_rule(Rule::from_str("action=return protocol=tcp").unwrap());
        ch.add_rule(Rule::from_str("action=drop").unwrap());
        check!(ch.len() == 2);

        let opt_chain = optimize_chain(&ch);
        check!(opt_chain.len() == 2);

        // Am unconditional return rule discards everything following it
        let mut ch = Chain::new("test");

        ch.add_rule(Rule::from_str("action=return").unwrap());
        ch.add_rule(Rule::from_str("action=drop").unwrap());
        check!(ch.len() == 2);

        let opt_chain = optimize_chain(&ch);
        check!(opt_chain.len() == 1);

        // What's left is the return rule
        let action = opt_chain.rules[0].action.as_ref().unwrap();
        check!(*action == Action::Return);
    }

    #[rstest]
    fn test_optimize_unconditional_action() {
        // A conditional accept (proto=tcp) doesn't get optimized out
        let mut ch = Chain::new("test");

        ch.add_rule(Rule::from_str("action=accept protocol=tcp").unwrap());
        ch.add_rule(Rule::from_str("action=drop").unwrap());
        check!(ch.len() == 2);

        let opt_chain = optimize_chain(&ch);
        check!(opt_chain.len() == 2);

        // Am unconditional accept rule discards everything following it
        let mut ch = Chain::new("test");

        ch.add_rule(Rule::from_str("action=accept").unwrap());
        ch.add_rule(Rule::from_str("action=drop").unwrap());
        check!(ch.len() == 2);

        let opt_chain = optimize_chain(&ch);
        check!(opt_chain.len() == 1);

        // What's left is the accept rule
        let action = opt_chain.rules[0].action.as_ref().unwrap();
        check!(*action == Action::Accept);
    }

    #[rstest]
    fn test_chain_optimizations(log_rule: Rule) {
        let mut ch = Chain::new("input");

        ch.add_rule(log_rule);
        ch.add_rule(Rule::from_str("action=accept").unwrap());

        check!(ch.len() == 2);
    }
}
