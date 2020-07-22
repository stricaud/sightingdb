use hex;
use sha2::{Sha512, Digest};

use crate::attribute::Attribute;

// pub fn store_attribute(attr: Attribute)
pub fn store_attribute(db_path: &String, namespace: &String, attr: &Attribute)
{
	let mut hasher = Sha512::new();
	hasher.update(b"Yo man!");
	let result = hasher.finalize();
	println!("Out:{}", hex::encode(&result[..]));
	println!("storing in namespace: '{}' value '{}'", namespace, attr.value);
}
