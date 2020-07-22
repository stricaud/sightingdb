// extern crate base64;
// use base64::{decode_config, encode_config, URL_SAFE_NO_PAD};

use crate::db::Database;

pub fn write(db: &mut Database, path: &str, value: &str, timestamp: i64) -> bool {
    db.write(path, value, timestamp, 0, true, true);
    true
}
