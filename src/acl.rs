use crate::db::{APIKEYS_NAMESPACE, Database};

/// Whether `authkey` may read `_namespace`.
///
/// NOTE: `_namespace` is currently ignored — any registered key grants access
/// to every namespace. Per-namespace permissions are still to be built; until
/// then an API key is an all-or-nothing credential.
pub fn can_read(db: &Database, authkey: &str, _namespace: &str) -> bool {
    is_registered(db, authkey)
}

/// Whether `authkey` may write `_namespace`. See the caveat on [`can_read`].
pub fn can_write(db: &Database, authkey: &str, _namespace: &str) -> bool {
    is_registered(db, authkey)
}

fn is_registered(db: &Database, authkey: &str) -> bool {
    db.namespace_exists(&format!("{APIKEYS_NAMESPACE}{authkey}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::DEFAULT_APIKEY;

    #[test]
    fn a_registered_key_is_accepted() {
        let db = Database::new();
        assert!(can_read(&db, DEFAULT_APIKEY, "any/ns"));
        assert!(can_write(&db, DEFAULT_APIKEY, "any/ns"));
    }

    #[test]
    fn an_unknown_key_is_rejected() {
        let db = Database::new();
        assert!(!can_read(&db, "nope", "any/ns"));
        assert!(!can_write(&db, "nope", "any/ns"));
    }

    #[test]
    fn an_empty_key_does_not_match_the_apikeys_namespace() {
        let db = Database::new();
        assert!(!can_read(&db, "", "any/ns"));
    }
}
