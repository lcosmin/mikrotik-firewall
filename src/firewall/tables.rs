use super::chains::{Chain, ChainBuilder};
use anyhow::{anyhow, Result};
use indexmap::IndexMap;
use std::collections::HashSet;
use tracing::debug;

/// Type alias for firewall tables
pub(crate) type Tables = IndexMap<String, Table>;

/// Firewall table. Contains one or multiple chains
#[derive(Clone, Debug)]
pub(crate) struct Table {
    pub chains: IndexMap<String, Chain>,
    pub name: String,
}

impl Table {
    pub fn optimize(self) -> Self {
        // TODO: optimization statistics, how many chains/rules eliminated.
        // TODO: should be called multiple times until no more changes; should return a bool if changed or not ?
        // TODO: if a chain jumps directly to another chain (first rule) and there's only this jump rule in the chain,
        //       optimize it by a direct jump to the target chain;

        let mut chains_to_remove: HashSet<String> = HashSet::new();

        // Table optimization:
        //
        // - create new table
        // - optimize each chain individually
        // - mark empty chains for removal
        // - remove calls to chains that return imediately
        // - truncate chains which jump to final chains
        //

        let mut new_tb = TableBuilder::new().name(&self.name).unwrap();

        // FIXME: revamp debug messages

        //
        // Pass 1:
        //  - optimize chains individually
        //  - mark empty ones for removal
        //  - mark the ones that return immediately
        //  - record final chains and pass them the second stage optimization
        //
        debug!(target: "optimize", "optimizing chains...");

        let mut final_chains = HashSet::new();

        for (_, chain) in self.chains.into_iter() {
            let chain = chain.optimize(None);

            // Test for empty chains
            if chain.is_empty() {
                debug!(target: "optimize", "found empty chain '{}'", &chain.name);
                chains_to_remove.insert(chain.name.clone());
                continue;
            }

            // Test for chain that immediately returns
            if chain.returns_unconditionally() {
                debug!(target: "optimize", "chain '{}' returns immediately", &chain.name);
                chains_to_remove.insert(chain.name.clone());
                continue;
            }

            if chain.is_final() {
                final_chains.insert(chain.name.clone());
            }

            new_tb = new_tb.chain(chain);
        }

        let table = new_tb.build().unwrap();

        // Pass 2:
        // - create new table
        // - optimize chain again, to remove rules after jumping to a final chains
        // - find and remove any references to chains removed at step 1

        let mut new_tb = TableBuilder::new().name(&table.name).unwrap();

        // - iterate all remaining rules and remove those referencing the removed chains
        for (_, chain) in table.chains.into_iter() {
            let mut new_cb = ChainBuilder::new().name(&chain.name).unwrap();

            // Optimize again, now knowing which chains are final (i.e. they don't return
            // to the caller); rules following jumps to such chains will be removed.
            let chain = chain.optimize(Some(&final_chains));

            for rule in chain.rules.into_iter() {
                if rule.is_jump() {
                    let jump_target = rule.jump_target.as_ref().expect("get jump target");

                    // References a removed chain? If so, remove this rule (chain doesn't exist anymore)
                    if chains_to_remove.contains(jump_target) {
                        debug!(target: "optimize", "[chain {}] removing rule that jumps to removed chain: {}", 
                        &chain.name, rule);
                        continue;
                    }
                }
                new_cb = new_cb.rule(rule);
            }

            new_tb = new_tb.chain(new_cb.build().unwrap());
        }

        new_tb.build().unwrap()
    }

    pub fn serialize(&self) -> Result<Vec<String>> {
        let mut res: Vec<String> = Vec::new();

        for (_, chain) in self.chains.iter() {
            for rule in chain.serialize()? {
                res.push(rule);
            }
        }

        Ok(res)
    }
}

#[derive(Clone)]
pub struct TableBuilder {
    chains: IndexMap<String, Chain>,
    table_name: Option<String>,
}

impl TableBuilder {
    pub fn new() -> Self {
        Self {
            chains: IndexMap::new(),
            table_name: None,
        }
    }

    pub fn name(self, name: &str) -> Result<Self> {
        match name {
            "filter" | "mangle" | "nat" | "raw" => {}
            _ => {
                return Err(anyhow!("invalid table name '{}'", name));
            }
        }

        Ok(Self {
            table_name: Some(name.to_string()),
            ..self
        })
    }

    pub fn chain(self, chain: Chain) -> Self {
        let mut res = self.clone();

        res.chains.insert(chain.name.clone(), chain);
        res
    }

    pub fn build(self) -> Result<Table> {
        if self.table_name.is_none() {
            return Err(anyhow!("table name not set"));
        }

        Ok(Table {
            name: self.table_name.unwrap(),
            chains: self.chains,
        })
    }
}

// FIXME: add tests for tables
