use crate::db::Database;
use serde::Serialize;

#[derive(Serialize)]
pub struct Message {
    message: String,
}

// #[derive(Deserialize)]
// struct NotFound {
//     error: String,
//     path: String,
//     value: String
// }

pub fn read(db: &mut Database, path: &str, value: &str, with_stats: bool, with_shadow: bool) -> String {
    if path.starts_with("_config/") {
        let err = serde_json::to_string(&Message {
            message: String::from("No access to _config namespace from outside!"),
        })
        .unwrap();
        return err;
    }

    let consensus = db.get_count(&"_all".to_string(), value);
    let attr = db.get_attr(path, value, with_stats, consensus);
    
    // Shadow Sightings
    if with_shadow {
        let mut shadow_path: String = "_shadow/".to_owned();
        shadow_path.push_str(path);
        // _shadow does not write the consensus
        db.write(&shadow_path, value, 0, 0, false, true);
    }
    
    attr
}

pub fn read_namespace(db: &mut Database, namespace: &str) -> String {
    if namespace.starts_with("_config/") {
        let err = serde_json::to_string(&Message {
            message: String::from("No access to _config namespace from outside!"),
        })
        .unwrap();
        return err;
    }

    let namespace_with_values = db.get_namespace_attrs(namespace);

    namespace_with_values
}

// Our internal reading does not trigger shadow sightings.
// USELESS FOR NOW, but will need to reactivate once we have the possibility to skip shadow if we want to
// pub fn read_internal(db: &mut Database, path: &str, value: &str, with_stats: bool) -> String {
//     let consensus = db.get_count(&"_all".to_string(), value);
//     let attr = db.get_attr(path, value, with_stats, consensus);

//     return attr;
// }
