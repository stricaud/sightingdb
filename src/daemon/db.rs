use std::collections::HashMap;
use serde::{Serialize};
use regex::Regex;

use crate::attribute::Attribute;

pub struct Database {
    db_path: String, // Where are DB is stored on disk
    hashtable: HashMap<String, HashMap<String, Attribute>>,
    re_stats: Regex,
}

#[derive(Serialize)]
pub struct DbError {
    error: String,
    path: String,
    value: String,
}

impl Database {
    pub fn new() -> Database {
        let mut db = Database {
            db_path: String::from(""),
            hashtable: HashMap::new(),
            // "stats":{"1586548800":1},
            re_stats: Regex::new(r"\x22stats\x22:\{.+\},").unwrap(),
        };
        // We initialize the default apikey: 'changeme'
        let attr = Attribute::new("");
        let mut tmphash = HashMap::new();
        tmphash.insert("".to_string(), attr);
        db.hashtable.insert("_config/acl/apikeys/changeme".to_string(), tmphash);
        return db;
    }
    pub fn set_db_path(&mut self, path: String) {
        self.db_path = path;
    }
    // Return the count of the written value
    pub fn write(&mut self, path: &str, value: &str, timestamp: i64, write_consensus: bool) -> u128 {
        let valuestable = self.hashtable.get_mut(&path.to_string());
        let mut new_value_to_path = false;
        let retval;
        
        match valuestable {
            Some(valuestable) => {
                //let mut valuestable = self.hashtable.get_mut(&path.to_string()).unwrap();
                let attr = valuestable.get(&value.to_string());
                match attr {
                    Some(_attr) => {
                        let iattr = valuestable.get_mut(&value.to_string()).unwrap();
                        if timestamp > 0 {
                            iattr.incr_from_timestamp(timestamp);
                        } else {
                            iattr.incr();
                        }
                        retval = iattr.count;
                    },
                    None => {
                        // New Value to existing path
                        let mut iattr = Attribute::new(&value);
                        if timestamp > 0 {
                            iattr.incr_from_timestamp(timestamp);
                        } else {
                            iattr.incr();
                        }

                        retval = iattr.count;
                        
                        valuestable.insert(value.to_string(), iattr);
                        new_value_to_path = true;
                    },
                }
            },
            None => {
                // New Value to a path that does not exist
                let mut newvaluestable = HashMap::new();
                let mut iattr = Attribute::new(&value);
                if timestamp > 0 {
                    iattr.incr_from_timestamp(timestamp);
                } else {
                    iattr.incr();
                }
                
                retval = iattr.count;
                
                newvaluestable.insert(value.to_string(), iattr);
                self.hashtable.insert(path.to_string(), newvaluestable);
                new_value_to_path = true;
            },
        }

        if new_value_to_path == true && write_consensus == true {
            // Check for consensus
            // Do we have the value in _all? If not then
            // we add it and consensus is the count of the
            // value from _all.
            self.write(&"_all".to_string(), value, 0, false);
        }
        
        return retval;
    }
    pub fn new_consensus(&mut self, path: &str, value: &str, consensus_count: u128) -> u128 {
        let valuestable = self.hashtable.get_mut(&path.to_string()).unwrap();
        let attr = valuestable.get_mut(&value.to_string());
        match attr {
            Some(_attr) => {
                let iattr = valuestable.get_mut(&value.to_string()).unwrap();
                iattr.set_consensus(consensus_count);
                return iattr.consensus;
            },
            None => {
                return 0;
            },            
        };
    }
    pub fn get_count(&mut self, path: &str, value: &str) -> u128 {
        let valuestable = self.hashtable.get_mut(&path.to_string());
        match valuestable {
            Some(valuestable) => {
                let attr = valuestable.get_mut(&value.to_string());
                match attr {
                    Some(attr) => { return attr.count(); },
                    None => {
                        return 0;
                    },            
                };
            },
            None => {
                return 0;
            },
        };
    }
    pub fn namespace_exists(&mut self, namespace: &str) -> bool {
        let valuestable = self.hashtable.get_mut(&namespace.to_string());

        match valuestable {
            Some(_) => {
                return true;
            },
            None => {
                return false;
            },
        }
    }
    
    pub fn get_attr(&mut self, path: &str, value: &str, with_stats: bool, consensus_count: u128) -> String {        
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
                        
                        // FIXME: There MUST be a better way to handle the stats de-serialization
                        // in short I want to store stats with attributes, but at the same time
                        // not send them everytime one want to fetch an attribute, only
                        // when the user requests the statistics. Otherwise it can be rather large.
                        // I find regex more elegant (and faster) than deserializing to reserialize.
                        // Maybe I should use deserialize_with, but I could not find a great way to
                        // use it for what I want. Open to suggestions here :)
                        let jattr = serde_json::to_string(&attr).unwrap();
                        if with_stats {
                            return jattr;
                        }
                        let nostats = self.re_stats.replace(&jattr, "");
                        return nostats.to_string();                        
                    },
                    None => {
                        let err = serde_json::to_string(&DbError{error: String::from("Value not found"), path: path.to_string(), value: value.to_string()});
                        return err.unwrap();
                    }
                }
            },
            None => {
                let err = serde_json::to_string(&DbError{error: String::from("Path not found"), path: path.to_string(), value: value.to_string()});
                return err.unwrap();
            },
        }
        // return String::from(""); // unreachable statement, however I want to make it clear this is our default
    }

    pub fn delete(&mut self, namespace: &str) -> bool {
        let res = self.hashtable.remove(&namespace.to_string());
        match res {
            Some(_) => {
                return true;
            },
            None => {
                return false;
            },
        }
    }

}
