use serde::Serialize;
use std::collections::HashMap;

use crate::attribute::Attribute;
use crate::db_log::log_attribute;

pub struct Database {
    db_path: String,
    // Where are DB is stored on disk
    hashtable: HashMap<String, HashMap<String, Attribute>>
}

#[derive(Serialize)]
pub struct DbError {
    error: String,
    namespace: String,
    value: String,
}

impl Database {
    pub fn new() -> Database {
        let mut db = Database {
            db_path: String::from(""),
            hashtable: HashMap::new(),
        };
        // We initialize the default apikey: 'changeme'
        let attr = Attribute::new("");
        let mut tmphash = HashMap::new();
        tmphash.insert("".to_string(), attr);
        db.hashtable
            .insert("_config/acl/apikeys/changeme".to_string(), tmphash);
        db
    }
    pub fn set_db_path(&mut self, path: String) {
        self.db_path = path;
    }
    // Return the count of the written value
    pub fn write(
        &mut self,
        path: &str,
        value: &str,
        timestamp: i64,
        write_consensus: bool,
    ) -> u128 {
        let (attr, new_value_to_path) = match self.hashtable.get_mut(path) {
            Some(valuestable) => {
                match valuestable.get_mut(value) {
                    // New attribute in a path that exists
                    None => {
                        let mut attr = Attribute::new(value);
                        attr.increment(timestamp);
                        valuestable.insert(value.to_string(), attr.clone());
                        (attr, false)
                    }
                    // Update to an existing attribute
                    Some(attr) => {
                        attr.increment(timestamp);
                        (attr.clone(), true)
                    }
                }
            }
            None => {
                // New value to a path that does not exist
                let mut newvaluestable = HashMap::new();
                let mut attr = Attribute::new(value);
                attr.increment(timestamp);
                newvaluestable.insert(value.to_string(), attr.clone());
                self.hashtable.insert(path.to_string(), newvaluestable);
                (attr, true)
            }
        };


        if new_value_to_path && write_consensus {
            // Check for consensus
            // Do we have the value in _all? If not then
            // we add it and consensus is the count of the
            // value from _all.
            self.write(&"_all".to_string(), value, 0, false);
        }
        log_attribute(path, &attr);
        attr.count
    }

    pub fn new_consensus(&mut self, path: &str, value: &str, consensus_count: u128) -> u128 {
        let valuestable = self.hashtable.get_mut(&path.to_string()).unwrap();
        let attr = valuestable.get_mut(&value.to_string());
        match attr {
            Some(_attr) => {
                let iattr = valuestable.get_mut(&value.to_string()).unwrap();
                iattr.set_consensus(consensus_count);
                iattr.consensus
            }
            None => 0,
        }
    }
    pub fn get_count(&mut self, path: &str, value: &str) -> u128 {
        let valuestable = self.hashtable.get_mut(&path.to_string());
        match valuestable {
            Some(valuestable) => {
                let attr = valuestable.get_mut(&value.to_string());
                match attr {
                    Some(attr) => attr.count(),
                    None => 0,
                }
            }
            None => 0,
        }
    }
    pub fn namespace_exists(&mut self, namespace: &str) -> bool {
        let valuestable = self.hashtable.get_mut(&namespace.to_string());
        valuestable.is_some()
    }

    pub fn get_namespace_attrs(&mut self, namespace: &str) -> String {
        let valuestable = self.hashtable.get_mut(&namespace.to_string());

        match valuestable {
            Some(valuestable) => {
                let mut response: HashMap<&str, Vec<&Attribute>> = HashMap::new();
                response.insert("attributes", valuestable.iter().map(|(_, attr)| attr).collect::<Vec<_>>());
                serde_json::to_string(&response).unwrap()
            }
            None => {
                let err = serde_json::to_string(&DbError {
                    error: String::from("Namespace not found"),
                    namespace: namespace.to_string(),
                    value: "".to_string(),
                });
                err.unwrap()
            }
        }
    }

    pub fn get_attr(
        &mut self,
        path: &str,
        value: &str,
        with_stats: bool,
        consensus_count: u128,
    ) -> String {
        let valuestable = self.hashtable.get_mut(&path.to_string());

        match valuestable {
            Some(valuestable) => {
                let attr = valuestable.get_mut(&value.to_string());
                match attr {
                    Some(attr) => {
                        if attr.ttl > 0 {
                            println!("FIXME, IMPLEMENT TTL. {:?}", attr);
                        }
                        attr.consensus = consensus_count;

                        if with_stats {
                            attr.serialize_with_stats().unwrap()
                        } else {
                            serde_json::to_string(attr).unwrap()
                        }
                    }
                    None => {
                        let err = serde_json::to_string(&DbError {
                            error: String::from("Value not found"),
                            namespace: path.to_string(),
                            value: value.to_string(),
                        });
                        err.unwrap()
                    }
                }
            }
            None => {
                let err = serde_json::to_string(&DbError {
                    error: String::from("Path not found"),
                    namespace: path.to_string(),
                    value: value.to_string(),
                });
                err.unwrap()
            }
        }
        // return String::from(""); // unreachable statement, however I want to make it clear this is our default
    }

    pub fn delete(&mut self, namespace: &str) -> bool {
        let res = self.hashtable.remove(&namespace.to_string());
        res.is_some()
    }
}

impl Default for Database {
    fn default() -> Self {
        Self::new()
    }
}
