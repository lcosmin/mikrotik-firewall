use anyhow::Result;

use super::structures::{Firewall, Parameter, Rule};
use super::utils::escape;

/// Trait which defines the method for saving a firewall
pub trait FirewallSerializer {
    /// Returns the firewall serialized to a string
    fn serialize(&self, fw: &Firewall) -> Result<String>;
    fn serialize_rule(&self, r: &Rule) -> Result<String>;
}

/// Structure which implements traits for saving a firewall for Mikrotik
pub struct Mikrotik;

impl Mikrotik {
    pub fn new() -> Mikrotik {
        Mikrotik {}
    }
}

impl FirewallSerializer for Mikrotik {
    fn serialize_rule(&self, r: &Rule) -> Result<String> {
        // preallocate a maximum possible size for the result vector
        let mut result: Vec<String> = Vec::with_capacity(r.params.len() + 2);

        // Write the action
        if let Some(ref action) = r.action {
            result.push(format!("action={}", action.as_str()));
        }

        // Write the jump-target, if any
        if let Some(ref jump_target) = r.jump_target {
            result.push(format!("jump-target={}", jump_target));
        }

        for arg in r.params.iter() {
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

    fn serialize(&self, fw: &Firewall) -> Result<String> {
        let mut result: Vec<String> = Vec::new();

        // Iterate all tables
        for (table, table_data) in fw.tables.iter() {
            // Iterate chains in each table
            for (chain, chains_data) in table_data.chains.iter() {
                // Iterate rules in each chain
                for rule in chains_data.rules.iter() {
                    // TODO:  ipv4 vs ipv6, how ??

                    let s = format!(
                        "/ip/firewall/{}/add chain={} {}",
                        &table,
                        &chain,
                        self.serialize_rule(rule)?
                    );

                    result.push(s);
                }
            }
        }

        Ok(result.join("\n"))
    }
}

#[cfg(test)]
mod tests {

    use super::FirewallSerializer;
    use super::{Mikrotik, Rule};
    use crate::firewall::testing::accept_rule;
    use assert2::check;
    use rstest::rstest;
    use std::collections::{HashMap, HashSet};
    use std::path::{Path, PathBuf};
    use std::str::FromStr;

    use crate::firewall::structures::{Chain, Firewall, Table, Tables};
    use crate::firewall::testing::{mikrotik, test_dir};

    #[rstest]
    fn test_serialize_rule(mikrotik: Mikrotik) {
        let line = "action=jump jump-target=foobar comment=\"Hello world\" in-interface-list=VPN";

        let r = Rule::from_str(line).unwrap();

        check!(mikrotik.serialize_rule(&r).unwrap() == line.to_string());
    }

    #[rstest]
    fn test_serialize_firewall(mikrotik: Mikrotik, test_dir: PathBuf, accept_rule: Rule) {
        let mut tables = Tables::new();

        let mut filter_table = Table::new();

        let mut chain = Chain::new("input");
        chain.add_rule(accept_rule);

        filter_table.chains.insert("input".to_string(), chain);

        tables.insert("filter".to_string(), filter_table);

        let fw = Firewall {
            //path: &fw_path,
            zones: HashSet::new(),
            policies: HashMap::new(),
            tables,
        };

        let result = mikrotik.serialize(&fw).unwrap();

        check!(result == "/ip/firewall/filter/add chain=input action=accept".to_string());
    }
}
