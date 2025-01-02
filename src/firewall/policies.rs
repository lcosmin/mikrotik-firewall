use crate::firewall::rules::Rule;
/// Type alias for firewall policies
use std::collections::HashMap;

pub(crate) type Policies = HashMap<String, Policy>;

#[derive(Debug)]
pub(crate) struct Policy {
    pub rules: Vec<Rule>,
}

impl Policy {
    pub fn new() -> Self {
        Self { rules: vec![] }
    }
}
