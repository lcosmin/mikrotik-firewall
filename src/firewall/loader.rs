use std::collections::HashSet;
use std::io;
use std::path::PathBuf;

use anyhow::{anyhow, Result};
use minijinja::context;
use tracing::{debug, error, info};

use crate::firewall::policies::Policy;

use super::config_files::{self, ConfigFile};
use super::parser;
use super::templates::Jinja;
use super::{
    chains::ChainBuilder, firewalls::Firewall, policies::Policies, tables::Table,
    tables::TableBuilder, tables::Tables, zones::Zones,
};

fn load_zones(cfg: &ConfigFile) -> Result<Zones> {
    let mut zones = Zones::new();

    debug!("loading zones...");
    cfg.zones.iter().for_each(|zd| {
        let name = zd.name.clone();
        zones.insert(name);
    });

    Ok(zones)
}

fn load_policies(cfg: &ConfigFile, zones: &Zones, jinja: &Jinja) -> Result<Policies> {
    debug!("loading input policies...");
    let mut expanded_chain_names = HashSet::new();

    let mut policies = Policies::new();

    for policy in cfg.policies.iter() {
        // Generate combinations of all possible 'from' and 'to' zones and use them to
        // expand both policy rules and chain names. This might not be needed, but we'll
        // break early

        'stop: for from in zones.iter() {
            for to in zones.iter() {
                let mut p: Policy = Policy::new();

                let ctx = context! {
                    from => from,
                    to => to,
                };

                let chain_name = jinja.expand_template(&ctx, &policy.chain)?;

                if expanded_chain_names.contains(&chain_name) {
                    // This chain name was generated before; if we're dealing with a template-able
                    // chain name, continue the loop, otherwise break

                    if policy.chain.contains("{{") {
                        continue;
                    }

                    break 'stop;
                }

                debug!(target: "load-policies", "from: {} to: {} chain: {}", &from, &to, &chain_name);

                // Dealing with a policy from ZONE to same ZONE ?
                if from == to && !cfg.options.same_zone_policy.is_none() {
                    for r in cfg.options.same_zone_policy.as_ref().unwrap().iter() {
                        let rule = parser::expand_string_and_parse_rule(&jinja, Some(&ctx), r)?;
                        p.rules.push(rule);
                    }
                } else {
                    //
                    // Parse rules for this `from`-`to` combination
                    //
                    for r in policy.rules.iter() {
                        let rule = parser::expand_string_and_parse_rule(&jinja, Some(&ctx), r)?;
                        p.rules.push(rule);
                    }
                }

                if p.rules.len() == 0 {
                    return Err(anyhow!("no rules defined for chain {}", &policy.chain));
                }

                expanded_chain_names.insert(chain_name.clone());

                policies.insert(chain_name, p);
            }
        }
    }
    Ok(policies)
}

pub fn load(path: &PathBuf) -> Result<Firewall> {
    // Load the configuration file
    let cfg = config_files::ConfigFile::load(path)?;

    let jinja = Jinja::new(path)?;

    // Process the configuration file:
    // - options
    // - zones
    // - policies

    //
    // Load all zones defined in the file
    //
    let zones = load_zones(&cfg).map_err(|e| anyhow!(" zones from config: {}", e))?;

    //
    // Load policies
    //
    let policies = load_policies(&cfg, &zones, &jinja)
        .map_err(|e| anyhow!("error loading policies from config: {}", e))?;

    let mut tables = Tables::new();

    let firewall_tables = vec!["filter", "mangle", "raw", "nat"];

    for table_name in firewall_tables.iter() {
        let table = match load_table_from_file(&jinja, table_name, &path, &zones, &policies) {
            Err(err) => {
                if let Some(err) = err.downcast_ref::<io::Error>() {
                    if err.kind() == io::ErrorKind::NotFound {
                        error!("table file '{}' not found", &table_name);
                        continue;
                    }
                }
                error!("error loading table '{}': {}", &table_name, err);
                return Err(anyhow!("error loading table '{}'", &table_name));
            }
            Ok(t) => t,
        };

        tables.insert(table_name.to_string(), table);
    }

    Ok(Firewall {
        zones,
        policies,
        tables,
    })
}

/// Compiles the specified firewall table by loading it from a file
fn load_table_from_file(
    jinja: &Jinja,
    fwtable: &str,
    base_dir: &PathBuf,
    zones: &Zones,
    policies: &Policies,
) -> Result<Table> {
    info!(target: "load-table", "loading table '{}'", fwtable);

    let ctx = context! {
        zones => zones,
    };

    let template_path = base_dir.join(fwtable);
    let rendered_fw = jinja.expand_template_from_file(&ctx, &template_path)?;

    //debug!(target: "load-table", "rendered table: \n{}", &rendered_fw);

    let fw_table_data: serde_yaml::Value = serde_yaml::from_str(&rendered_fw)?;

    if let Some(m) = fw_table_data.as_mapping() {
        Ok(compile_fw_table(&jinja, fwtable, m, &policies)?)
    } else {
        Err(anyhow!("file structure error"))
    }
}

/// Processes data loaded from a file representing a firewall table and returns
/// a [Table] structure.
fn compile_fw_table(
    jinja: &Jinja,
    name: &str,
    m: &serde_yaml::Mapping,
    policies: &Policies,
) -> Result<Table> {
    let mut tb = TableBuilder::new().name(name)?;

    // TODO: have a statistics object which collects which policies haven't been used, among other things

    debug!(target: "compile-table", "processing table '{}' from file", name);

    // A firewall table contains multiple chains as a mapping; iterate and
    // convert them to the internal structures
    for (k, v) in m.iter() {
        let chain_name = k.as_str().unwrap();

        let mut chain_builder = ChainBuilder::new().name(chain_name)?;

        let ch: config_files::Chain = serde_yaml::from_value(v.clone()).expect("process chain");

        // traverse the chain's rules, convert them to internals::Rule, apply the chain's policy, if any
        // then apply the regular policy

        for r in ch.rules.iter() {
            // Add chain rules
            let rule = parser::expand_string_and_parse_rule(jinja, None, r)?;
            chain_builder = chain_builder.rule(rule);
        }

        // Add the chain's policy, if it's defined in the file
        if let Some(policy) = ch.policy {
            debug!(target: "compile-table", "adding file defined policy for chain '{}'", &chain_name);

            for p in policy.iter() {
                let rule = parser::expand_string_and_parse_rule(jinja, None, p)?;
                chain_builder = chain_builder.rule(rule);
            }
        } else if let Some(policy) = policies.get(chain_name) {
            // Add the chain's policy, if any is defined in the configuration file
            debug!(target: "compile-table", "adding default policy for chain '{}'", &chain_name);

            chain_builder = policy
                .rules
                .iter()
                .fold(chain_builder, |cb, rule| cb.rule(rule.clone()));
        } else {
            debug!(target: "compile-table", "no default policy for chain '{}'", &chain_name);
        }

        tb = tb.chain(chain_builder.build()?);

        debug!(target: "compile-table", "[{}] added chain {:?}", &name, chain_name);
    }

    Ok(tb.build()?)
}

#[cfg(test)]
mod tests {
    use crate::firewall::testing::test_dir;
    use assert2::{assert, check};
    use rstest::rstest;
    use std::path::{Path, PathBuf};

    use super::{load, load_zones, ConfigFile};

    #[rstest]
    fn test_load_zones(test_dir: PathBuf) {
        let fw_path = test_dir.join(Path::new("load_fw_1"));
        let cfg = ConfigFile::load(&fw_path).unwrap();
        let res = load_zones(&cfg);

        assert!(res.is_ok());

        let zones = res.unwrap();

        check!(zones.len() == 2);
    }

    #[rstest]
    fn test_firewall_loader(test_dir: PathBuf) {
        let fw_path = test_dir.join(Path::new("load_fw_1"));

        let res = load(&fw_path);
        check!(res.is_ok());

        let res = res.unwrap();

        check!(res.zones.len() == 2);
        check!(res.zones.contains("LAN"));
        check!(res.zones.contains("WAN"));

        check!(res.policies.len() == 4);
        check!(res.policies.contains_key("input"));
        check!(res.policies.contains_key("input-LAN"));
        check!(res.policies.contains_key("input-WAN"));
        check!(res.policies.contains_key("some-chain"));

        check!(res.tables.len() == 1);
        check!(res.tables.contains_key("filter"));
    }
}
