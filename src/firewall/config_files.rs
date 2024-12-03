//! Structures used for decoding data read from files
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;
use tracing::info;

use anyhow::Result;
use serde_yaml;

#[derive(Debug, Deserialize)]
pub struct ConfigPolicy {
    pub chain: String,
    pub rules: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct ConfigZone {
    pub name: String,
}

#[derive(Deserialize, Debug)]
pub struct ConfigOptions {
    // Rules which apply for templated "from" -> "to" rules when from == to
    pub same_zone_policy: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct ConfigFile {
    pub options: ConfigOptions,
    pub zones: Vec<ConfigZone>,
    pub policies: Vec<ConfigPolicy>,
}

impl ConfigFile {
    pub fn load(config_path: &PathBuf) -> Result<ConfigFile> {
        let mut p = config_path.clone();

        p.push("firewall.conf");

        info!("loading configuration file: {}", &config_path.display());

        let data = fs::read_to_string(p)?;

        let fw_conf: ConfigFile = serde_yaml::from_str(&data)?;

        Ok(fw_conf)
    }
}

/// A structure used to parse a firewall chain, defined in a file
#[derive(Debug, Deserialize)]
pub struct Chain {
    /// A set of rules which is applied after the rules in the `rules` section (policy). Used to
    /// define a more fine grained policy, in case the one defined in the firewall configuration
    /// file is not sufficient.
    pub policy: Option<Vec<String>>,
    /// Firewall rules
    pub rules: Vec<String>,
}
