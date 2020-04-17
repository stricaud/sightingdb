use crate::db::Database;

pub fn can_read(db: &mut Database, authkey: &str, _namespace: &str) -> bool
{
    let mut apikey_namespace = String::from("_config/acl/apikeys/");
    apikey_namespace.push_str(authkey);
    let attr = db.namespace_exists(&apikey_namespace);

    return attr;
}

pub fn can_write(db: &mut Database, authkey: &str, _namespace: &str) -> bool
{
    let mut apikey_namespace = String::from("_config/acl/apikeys/");
    apikey_namespace.push_str(authkey);
    let attr = db.namespace_exists(&apikey_namespace);

    return attr;
}
