use std::collections::HashSet;
use std::io;
use std::path::PathBuf;

use anyhow::{anyhow, Result};
use minijinja::context;
use tracing::{debug, error, info};

use crate::firewall::policies::Policy;
use crate::firewall::utils::ZoneCombiner;

use super::config_files::{self, ConfigFile};
use super::parser;
use super::templates::Jinja;
use super::{
    chains::ChainBuilder, firewalls::Firewall, policies::Policies, tables::TableBuilder,
    tables::Tables, zones::Zones,
};

pub struct FirewallLoader<'a> {
    base_dir: &'a PathBuf,
    cfg: ConfigFile,
    jinja: Jinja<'a>,
    zones: Zones,
    policies: Policies,
    tables: Tables,
}

impl<'a> FirewallLoader<'a> {
    pub fn load(path: &'a PathBuf) -> Result<Firewall> {
        // Load the configuration file
        let cfg = config_files::ConfigFile::load(path)?;

        let mut fw = Self {
            base_dir: path,
            cfg,
            jinja: Jinja::new(path)?,
            zones: Zones::new(),
            policies: Policies::new(),
            tables: Tables::new(),
        };

        fw.load_fw()
    }

    fn load_zones(&mut self) -> Result<()> {
        debug!("loading zones...");

        self.cfg.zones.as_ref().map_or(Ok(()), |zones| {
            zones.iter().try_for_each(|zone| {
                let name = zone.name.clone().to_uppercase();
                if self.zones.contains(&name) {
                    Err(anyhow!("zone '{}' already exists", &name))
                } else {
                    self.zones.insert(name);
                    Ok(())
                }
            })
        })
    }

    fn load_policies(&mut self) -> Result<()> {
        debug!("loading firewall policies");
        let mut expanded_chain_names = HashSet::new();

        let mut policies = Policies::new();

        for policy in self.cfg.policies.iter() {
            // Generate combinations of all possible 'from' and 'to' zones and use them to
            // expand both policy rules and chain names. This might not be needed, but we'll
            // break early
            for (from, to) in ZoneCombiner::new(&self.zones) {
                let mut p: Policy = Policy::new();

                let ctx = context! {
                    from => from,
                    to => to,
                };

                let chain_name = self.jinja.expand_template(&ctx, &policy.chain)?;

                if expanded_chain_names.contains(&chain_name) {
                    // This chain name was generated before; if we're dealing with a template-able
                    // chain name, continue the loop, otherwise break

                    if policy.chain.contains("{{") {
                        continue;
                    }
                    break;
                }

                //
                // Parse rules for this `from`-`to` combination
                //
                for r in policy.rules.iter() {
                    let rule = parser::expand_string_and_parse_rule(&self.jinja, Some(&ctx), r)?;
                    p.rules.push(rule);
                }

                if p.rules.len() == 0 {
                    return Err(anyhow!(
                        "no policy rules defined for chain {}",
                        &policy.chain
                    ));
                }

                expanded_chain_names.insert(chain_name.clone());

                debug!(target: "load-policies", "adding policies for chain '{}'", &chain_name);

                policies.insert(chain_name, p);
            }
        }

        self.policies = policies;
        Ok(())
    }

    fn load_fw(&mut self) -> Result<Firewall> {
        // Process the configuration file:
        // - options
        // - zones
        // - policies

        self.load_zones()
            .map_err(|e| anyhow!("error loading zones from config file: {}", e))?;

        self.load_policies()
            .map_err(|e| anyhow!("error loading policies from config file: {}", e))?;

        let firewall_tables = vec!["filter", "mangle", "raw", "nat"];

        for table_name in firewall_tables.iter() {
            match self.load_table_from_file(table_name) {
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
        }

        Ok(Firewall {
            tables: self.tables.clone(),
        })
    }

    /// Compiles the specified firewall table by loading it from a file
    fn load_table_from_file(&mut self, fwtable: &str) -> Result<()> {
        let log_target = format!("[table {}]", fwtable);

        info!(target: "load-table", "{} loading table", &log_target);

        let ctx = context! {
            zones => self.zones,
            policies => self.policies,
        };

        let template_path = self.base_dir.join(fwtable);
        let rendered_fw = self.jinja.expand_template_from_file(&ctx, &template_path)?;

        let fw_table_data: serde_yaml::Value = serde_yaml::from_str(&rendered_fw)?;

        let m = fw_table_data.as_mapping();
        if m.is_none() {
            return Err(anyhow!("file structure error"));
        }

        let m = m.unwrap();

        let mut tb = TableBuilder::new().name(fwtable)?;

        // TODO: have a statistics object which collects which policies haven't been used,
        //  among other things

        // A firewall table contains multiple chains as a mapping; iterate and
        // convert them to the internal structures
        for (k, v) in m.iter() {
            let chain_name = k.as_str().unwrap();

            let mut chain_builder = ChainBuilder::new().name(chain_name)?;

            let ch: config_files::Chain = serde_yaml::from_value(v.clone())?;

            // traverse the chain's rules, convert them to internals::Rule, apply the chain's policy, if any
            // then apply the regular policy

            for r in ch.rules.iter() {
                // Add chain rules
                let rule = parser::expand_string_and_parse_rule(&self.jinja, None, r)?;
                chain_builder = chain_builder.rule(rule);
            }

            // Add the chain's policy, if it's defined in the file
            if let Some(policy) = ch.policy {
                debug!(target: "load-table", "{} adding file defined policy for chain '{}'", 
                &log_target, &chain_name);

                for p in policy.iter() {
                    let rule = parser::expand_string_and_parse_rule(&self.jinja, None, p)?;
                    chain_builder = chain_builder.rule(rule);
                }
            } else if let Some(policy) = self.policies.get(chain_name) {
                // Add the chain's policy, if any is defined in the configuration file
                debug!(target: "load-table", "{} adding default policy for chain '{}'", &log_target, &chain_name);

                chain_builder = policy
                    .rules
                    .iter()
                    .fold(chain_builder, |cb, rule| cb.rule(rule.clone()));
            } else {
                debug!(target: "load-table", "{} no default policy for chain '{}'", &log_target, &chain_name);
            }

            tb = tb.chain(chain_builder.build()?);

            debug!(target: "load-table", "{} added chain '{}'", &log_target, chain_name);
        }

        let table = tb.build()?;

        self.tables.insert(fwtable.to_string(), table);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::FirewallLoader;
    use crate::firewall::testing::test_dir;
    use anyhow::Result;
    use assert2::check;
    use rstest::rstest;
    use std::path::{Path, PathBuf};

    // FIXME: test cases

    #[rstest]
    #[case("dup_zones_1")]
    #[case("dup_zones_2")]
    fn test_loader_dup_zones(test_dir: PathBuf, #[case] case: &str) -> Result<()> {
        let fw_path = test_dir.join(Path::new(case));

        let res = FirewallLoader::load(&fw_path);

        check!(res
            .is_err_and(|e| e.to_string()
                == "error loading zones from config file: zone 'LAN' already exists"));

        Ok(())
    }

    #[rstest]
    fn test_loader_bad_policies_1(test_dir: PathBuf) -> Result<()> {
        let fw_path = test_dir.join(Path::new("bad_policies_1"));

        let res = FirewallLoader::load(&fw_path);

        check!(res.is_err());

        check!(
            res.err().unwrap().to_string()
                == "error loading policies from config file: no policy rules defined for chain input"
        );

        Ok(())
    }

    #[rstest]
    fn test_firewall_loader(test_dir: PathBuf) -> Result<()> {
        let fw_path = test_dir.join(Path::new("load_fw_1"));

        let fw = FirewallLoader::load(&fw_path)?;

        check!(fw.tables.len() == 1);

        let ser = fw.serialize()?;

        check!(
            ser == vec![
            "/ip/firewall/filter/add chain=input action=jump jump-target=input-LAN in-interface-list=LAN",
            "/ip/firewall/filter/add chain=input action=jump jump-target=input-WAN in-interface-list=WAN",
            "/ip/firewall/filter/add chain=input action=accept",

            "/ip/firewall/filter/add chain=input-LAN action=accept",

            // default policy from firewall.conf
            "/ip/firewall/filter/add chain=input-LAN action=passthrough limit=\"1/1m,5:packet\" log=yes log-prefix=\"DROP-LAN\"",
            "/ip/firewall/filter/add chain=input-LAN action=drop",

            // default policy from firewall.conf
            "/ip/firewall/filter/add chain=input-WAN action=passthrough limit=\"1/1m,5:packet\" log=yes log-prefix=\"DROP-WAN\"",
            "/ip/firewall/filter/add chain=input-WAN action=drop",


            "/ip/firewall/filter/add chain=output action=accept",
            "/ip/firewall/filter/add chain=forward action=accept log=yes"

            ]
        );

        // Check the loaded structure

        Ok(())
    }
}
