use hex;
use sha2::{Sha512, Digest};

use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::path::{PathBuf};
//use serde::Serialize;

use walkdir::WalkDir;

use crate::db::Database;
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

pub fn retrieve_attributes(db: &mut Database)
{
    &db.reset();
    let dbpath = &db.get_db_path().clone();
    // println!("-->db dir:{}", dbpath.len());

    for entry in WalkDir::new(dbpath)
	.into_iter()
	.filter_map(|e| e.ok()) {
	    if entry.metadata().unwrap().is_file() {
		let mut attrfile = File::open(entry.path()).unwrap();
		let mut attrbuf = String::new();
		attrfile.read_to_string(&mut attrbuf);		
		let attr: Attribute = serde_json::from_str(&attrbuf).unwrap();
		
		let mut parent_dir = String::from(entry.path().parent().unwrap().to_str().unwrap());
		let namespace = parent_dir.split_off(dbpath.len());

		&db.write(&namespace, &attr.value, attr.last_seen.timestamp(), attr.count, false, false);
	    }
    }
    
}
