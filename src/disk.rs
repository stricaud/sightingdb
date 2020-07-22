use hex;
use sha2::{Sha512, Digest};
use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::path::{PathBuf};
//use serde::Serialize;

use crate::attribute::Attribute;

// pub fn store_attribute(attr: Attribute)
pub fn store_attribute(dbdir: &String, namespace: &String, attr: &Attribute)
{
    let mut hasher = Sha512::new();
    hasher.update(&attr.value);
    let result = hasher.finalize();
    let hexhash = hex::encode(&result[..]);
    
    // println!("storing in namespace: '{}' value '{}'", namespace, attr.value);
    let mut namespacedir = PathBuf::from(dbdir);
    namespacedir.push(namespace);
    let mut attrfile = PathBuf::from(&namespacedir);
    match fs::create_dir_all(namespacedir) {
	Ok(_) => {},
	Err(e) => { println!("Error creating the namespace dir: {}", e); }
    }
    let jattr = serde_json::to_string(&attr).unwrap();
    attrfile.push(&hexhash);

    let mut file = File::create(attrfile).unwrap();
    match file.write_all(jattr.as_bytes()) {
	Ok(_) => {},
	Err(e) => { println!("Error writing to database: {}", e); }
    }
}
