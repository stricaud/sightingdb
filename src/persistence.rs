use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::db::{Database, SNAPSHOT_VERSION, SnapshotData};

/// Snapshot file name inside `dbdir`.
pub const SNAPSHOT_FILE: &str = "sightingdb.json";

pub fn snapshot_path(dbdir: &Path) -> PathBuf {
    dbdir.join(SNAPSHOT_FILE)
}

/// Write the database to `path`, atomically.
///
/// The snapshot goes to a sibling temporary file which is flushed and synced
/// before being renamed into place, so a crash mid-write leaves the previous
/// snapshot intact rather than a half-written one.
pub fn save(db: &Database, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating snapshot directory {}", parent.display()))?;
    }

    let temp = path.with_extension("tmp");
    {
        let file = File::create(&temp).with_context(|| format!("creating {}", temp.display()))?;
        let mut writer = BufWriter::new(file);

        serde_json::to_writer(&mut writer, &db.snapshot())
            .with_context(|| format!("serializing the snapshot to {}", temp.display()))?;

        writer
            .flush()
            .with_context(|| format!("flushing {}", temp.display()))?;
        writer
            .get_ref()
            .sync_all()
            .with_context(|| format!("syncing {}", temp.display()))?;
    }

    fs::rename(&temp, path)
        .with_context(|| format!("renaming {} to {}", temp.display(), path.display()))?;

    Ok(())
}

/// Read a snapshot back, or `None` when there is nothing to restore.
pub fn load(path: &Path) -> Result<Option<SnapshotData>> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("opening {}", path.display())),
    };

    let data: SnapshotData = serde_json::from_reader(BufReader::new(file))
        .with_context(|| format!("parsing snapshot {}", path.display()))?;

    if data.version != SNAPSHOT_VERSION {
        bail!(
            "snapshot {} has version {}, but this build only understands version {}",
            path.display(),
            data.version,
            SNAPSHOT_VERSION
        );
    }

    Ok(Some(data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{DatabasePolicy, WriteOpts};
    use chrono::{DateTime, Utc};

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).expect("timestamp in range")
    }

    fn consensus() -> WriteOpts {
        WriteOpts {
            consensus: true,
            ttl: None,
        }
    }

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!("sightingdb-persist-{tag}"));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            TempDir(path)
        }

        fn snapshot(&self) -> PathBuf {
            snapshot_path(&self.0)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_database_survives_a_save_and_load() {
        let dir = TempDir::new("roundtrip");
        let db = Database::new();
        db.write("my/ns", "1.2.3.4", at(1_600_000_000), consensus());
        db.write("my/ns", "1.2.3.4", at(1_600_003_600), consensus());
        db.write("other/ns", "5.6.7.8", at(1_600_000_000), consensus());

        save(&db, &dir.snapshot()).unwrap();
        let restored = Database::from_snapshot(
            load(&dir.snapshot()).unwrap().unwrap(),
            DatabasePolicy::default(),
        );

        assert_eq!(restored.count("my/ns", "1.2.3.4"), 2);
        assert_eq!(restored.count("other/ns", "5.6.7.8"), 1);
        assert!(restored.has_any_apikey());
    }

    #[test]
    fn loading_a_missing_snapshot_is_not_an_error() {
        let dir = TempDir::new("missing");
        assert!(load(&dir.snapshot()).unwrap().is_none());
    }

    #[test]
    fn saving_creates_the_directory() {
        let dir = TempDir::new("mkdir");
        let nested = dir.0.join("a/b/c").join(SNAPSHOT_FILE);

        save(&Database::new(), &nested).unwrap();

        assert!(nested.exists());
    }

    #[test]
    fn saving_twice_leaves_no_temporary_file_behind() {
        let dir = TempDir::new("tmpfile");
        let db = Database::new();

        save(&db, &dir.snapshot()).unwrap();
        save(&db, &dir.snapshot()).unwrap();

        let leftovers: Vec<_> = fs::read_dir(&dir.0)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "left behind {leftovers:?}");
    }

    #[test]
    fn a_future_snapshot_version_is_refused() {
        let dir = TempDir::new("version");
        fs::write(dir.snapshot(), r#"{"version":999,"namespaces":{}}"#).unwrap();

        let err = load(&dir.snapshot()).unwrap_err().to_string();
        assert!(err.contains("version 999"), "{err}");
    }

    #[test]
    fn a_corrupt_snapshot_reports_the_file() {
        let dir = TempDir::new("corrupt");
        fs::write(dir.snapshot(), "{not json").unwrap();

        let err = load(&dir.snapshot()).unwrap_err().to_string();
        assert!(err.contains("parsing snapshot"), "{err}");
    }

    /// A crash part way through a write must not destroy the previous snapshot.
    #[test]
    fn a_stale_temporary_file_does_not_affect_loading() {
        let dir = TempDir::new("stale");
        let db = Database::new();
        db.write("ns", "v", at(1000), consensus());
        save(&db, &dir.snapshot()).unwrap();

        // Simulate a crash mid-save.
        fs::write(dir.snapshot().with_extension("tmp"), "{half writ").unwrap();

        let restored = Database::from_snapshot(
            load(&dir.snapshot()).unwrap().unwrap(),
            DatabasePolicy::default(),
        );
        assert_eq!(restored.count("ns", "v"), 1);
    }
}
