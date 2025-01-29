use super::tables::Tables;

use anyhow::Result;

#[derive(Debug)]
pub struct Firewall {
    pub tables: Tables,
}

impl Firewall {
    /// Create a firewall from the specified path (reads and processes files stored there)
    pub fn optimize(self) -> Result<Self> {
        let mut new_tables = Tables::new();

        // Optimize tables
        for (table_name, table) in self.tables.into_iter() {
            new_tables.insert(table_name.clone(), table.optimize());
        }

        Ok(Firewall {
            tables: new_tables,
            ..self
        })
    }

    pub fn serialize(&self) -> Result<Vec<String>> {
        let mut res = Vec::new();

        // serialize all tables
        for (_, table) in self.tables.iter() {
            // serialize current table, get all chains
            for chain in table.serialize().iter() {
                // TODO: various mikrotik versions, how ?
                // TODO:  ipv4 vs ipv6, how ??

                for rule in chain.iter() {
                    let command = format!("/ip/firewall/{}/add {}", &table.name, &rule);
                    res.push(command);
                }
            }
        }

        Ok(res)
    }
}
