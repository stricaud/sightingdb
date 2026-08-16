//! Saving and restoring the database.
//!
//! Storage is sharded by the first segment of a namespace, so `myorg/thisone`
//! lives in the shard `myorg`. That is what makes a snapshot cost what changed
//! rather than what exists: only shards written to since the last save are
//! rewritten. It is also the unit a namespace can later be paged in and out by.
//!
//! Each shard is JSON compressed with zstd. Measured on a 50 MB snapshot, zstd
//! reaches 8x in 0.34s and decompresses in 0.03s where xz reaches 12x but takes
//! 15.6s to compress and 0.19s to decompress — and decompression sits on the
//! path of a namespace being read back in.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

use crate::db::{Database, SNAPSHOT_VERSION, ShardData, SnapshotData};

/// Written by versions that kept everything in one file.
pub const LEGACY_SNAPSHOT: &str = "sightingdb.json";
const SHARD_SUFFIX: &str = ".json.zst";
/// Level 3 is the knee of the curve: 7.3x at 0.07s per 50 MB. Higher levels
/// buy little for a file rewritten every few minutes.
const DEFAULT_LEVEL: i32 = 3;

/// Namespaces with no segment of their own, which should not happen but must
/// still land somewhere.
const ROOT_SHARD: &str = "_internal";
/// Everything internal — `_all`, `_shadow/*`, `_config/*` — shares one shard,
/// kept apart from user data so that a shard file corresponds to something a
/// person actually organised.
pub const INTERNAL_SHARD: &str = "_internal";
/// The file that shard is written to. Named for the database rather than the
/// shard, since it is the one file that is always present.
const INTERNAL_FILE: &str = "sightingdb.json.zst";

/// The shard a namespace belongs to.
///
/// Internal namespaces all share one shard; everything else shards on its
/// first path segment, so `myorg/thisone` lives in `myorg`.
pub fn shard_of(namespace: &str) -> &str {
    let first = namespace
        .split('/')
        .find(|segment| !segment.is_empty())
        .unwrap_or(ROOT_SHARD);
    if first.starts_with('_') {
        INTERNAL_SHARD
    } else {
        first
    }
}

/// The file a shard is stored in.
///
/// Namespaces come from URLs, so the name is attacker-controlled and cannot be
/// used as a path: `../../etc/cron.d/x` would escape `dbdir`. Anything outside
/// a conservative set is percent-encoded, and a hash of the exact name is
/// appended so that two shards differing only in case — which collide on a
/// case-insensitive filesystem — still get separate files.
pub fn shard_file(dbdir: &Path, shard: &str) -> PathBuf {
    // Ours, not user-supplied, so it needs no encoding or hash. A user shard
    // always carries the hash suffix, so it can never produce this name.
    if shard == INTERNAL_SHARD {
        return dbdir.join(INTERNAL_FILE);
    }

    let mut safe = String::new();
    for c in shard.chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
            safe.push(c);
        } else {
            let mut buf = [0u8; 4];
            for byte in c.encode_utf8(&mut buf).as_bytes() {
                safe.push_str(&format!("%{byte:02X}"));
            }
        }
    }
    safe.truncate(80);

    let digest = Sha256::digest(shard.as_bytes());
    dbdir.join(format!(
        "{safe}-{:08x}{SHARD_SUFFIX}",
        u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]])
    ))
}

/// What a save did, for the log.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SaveReport {
    pub shards_written: usize,
    pub shards_skipped: usize,
    pub bytes: u64,
}

/// Write the shards that have changed since the last save.
///
/// `all` forces every shard out, which is what a shutdown wants.
pub fn save(db: &Database, dbdir: &Path, level: i32, all: bool) -> Result<SaveReport> {
    fs::create_dir_all(dbdir)
        .with_context(|| format!("creating snapshot directory {}", dbdir.display()))?;

    let present = db.shards();
    let dirty = db.take_dirty();
    let mut report = SaveReport::default();

    for shard in &present {
        if !all && !dirty.contains(shard) {
            report.shards_skipped += 1;
            continue;
        }
        match write_shard(db, dbdir, shard, level) {
            Ok(bytes) => {
                report.shards_written += 1;
                report.bytes += bytes;
            }
            Err(e) => {
                // Put it back so the next save retries rather than losing it.
                db.mark_shard_dirty(shard);
                return Err(e);
            }
        }
    }

    // A shard whose namespaces have all been deleted leaves a stale file.
    for shard in dirty.difference(&present.iter().cloned().collect()) {
        let path = shard_file(dbdir, shard);
        if path.exists() {
            let _ = fs::remove_file(&path);
        }
    }

    Ok(report)
}

fn write_shard(db: &Database, dbdir: &Path, shard: &str, level: i32) -> Result<u64> {
    let path = shard_file(dbdir, shard);
    let temp = path.with_extension("tmp");

    {
        let file = File::create(&temp).with_context(|| format!("creating {}", temp.display()))?;
        let writer = BufWriter::new(file);
        let mut encoder = zstd::Encoder::new(writer, level).context("starting the zstd encoder")?;

        serde_json::to_writer(&mut encoder, &db.shard_snapshot(shard))
            .with_context(|| format!("serializing shard {shard}"))?;

        let mut writer = encoder.finish().context("finishing the zstd stream")?;
        writer
            .flush()
            .with_context(|| format!("flushing {}", temp.display()))?;
        writer
            .get_ref()
            .sync_all()
            .with_context(|| format!("syncing {}", temp.display()))?;
    }

    let bytes = fs::metadata(&temp).map(|m| m.len()).unwrap_or(0);
    fs::rename(&temp, &path)
        .with_context(|| format!("renaming {} to {}", temp.display(), path.display()))?;
    Ok(bytes)
}

/// Read every shard back, plus a single-file snapshot from an older version.
pub fn load(dbdir: &Path) -> Result<Option<SnapshotData>> {
    let mut namespaces = HashMap::new();
    let mut found = false;

    // An older single-file snapshot is read first so that shards, which are
    // newer, win on any overlap.
    let legacy = dbdir.join(LEGACY_SNAPSHOT);
    if legacy.exists() {
        let file = File::open(&legacy).with_context(|| format!("opening {}", legacy.display()))?;
        let data: SnapshotData = serde_json::from_reader(BufReader::new(file))
            .with_context(|| format!("parsing {}", legacy.display()))?;
        check_version(data.version, &legacy)?;
        log::info!(
            "Read the single-file snapshot {}; it will be replaced by per-shard files on the \
             next save",
            legacy.display()
        );
        namespaces.extend(data.namespaces);
        found = true;
    }

    if dbdir.is_dir() {
        let mut files: Vec<PathBuf> = fs::read_dir(dbdir)
            .with_context(|| format!("listing {}", dbdir.display()))?
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| path.to_string_lossy().ends_with(SHARD_SUFFIX))
            .collect();
        files.sort();

        for path in files {
            let data = read_shard(&path)?;
            check_version(data.version, &path)?;
            namespaces.extend(data.namespaces);
            found = true;
        }
    }

    if !found {
        return Ok(None);
    }
    Ok(Some(SnapshotData {
        version: SNAPSHOT_VERSION,
        namespaces,
    }))
}

fn read_shard(path: &Path) -> Result<ShardData> {
    let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let decoder = zstd::Decoder::new(BufReader::new(file))
        .with_context(|| format!("decompressing {}", path.display()))?;
    serde_json::from_reader(decoder).with_context(|| format!("parsing {}", path.display()))
}

fn check_version(version: u32, path: &Path) -> Result<()> {
    if version != SNAPSHOT_VERSION {
        bail!(
            "{} has version {version}, but this build only understands version {}",
            path.display(),
            SNAPSHOT_VERSION
        );
    }
    Ok(())
}

/// Read one shard's namespaces, for paging it back into memory.
pub fn read_shard_file(
    dbdir: &Path,
    shard: &str,
) -> Result<HashMap<String, HashMap<String, crate::attribute::Attribute>>> {
    let path = shard_file(dbdir, shard);
    if !path.exists() {
        return Ok(HashMap::new());
    }
    let data = read_shard(&path)?;
    check_version(data.version, &path)?;
    Ok(data.namespaces)
}

/// Write one shard, used when evicting it rather than during a full save.
pub fn save_shard(db: &Database, dbdir: &Path, shard: &str, level: i32) -> Result<()> {
    fs::create_dir_all(dbdir)
        .with_context(|| format!("creating snapshot directory {}", dbdir.display()))?;
    write_shard(db, dbdir, shard, level).map(|_| ())
}

pub fn default_level() -> i32 {
    DEFAULT_LEVEL
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

    pub(super) struct TempDir(pub PathBuf);

    impl TempDir {
        pub(super) fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!("sightingdb-persist-{tag}"));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            TempDir(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    // -- sharding ----------------------------------------------------------

    #[test]
    fn a_namespace_shards_on_its_first_segment() {
        assert_eq!(shard_of("myorg/thisone/"), "myorg");
        assert_eq!(shard_of("feeds/misp/ips"), "feeds");
        assert_eq!(shard_of("plain"), "plain");
        assert_eq!(shard_of("/leading/slash"), "leading");
    }

    /// Internal bookkeeping shares one file, so a shard on disk always
    /// corresponds to something a person organised.
    #[test]
    fn internal_namespaces_share_one_shard() {
        for internal in [
            "_all",
            "_shadow/feeds/misp",
            "_config/acl/apikeys/x",
            "_anything",
        ] {
            assert_eq!(shard_of(internal), INTERNAL_SHARD, "{internal}");
        }
        assert_eq!(shard_of(""), INTERNAL_SHARD);
        assert_eq!(shard_of("///"), INTERNAL_SHARD);

        assert_eq!(
            shard_file(Path::new("/tmp"), INTERNAL_SHARD),
            Path::new("/tmp/sightingdb.json.zst")
        );
    }

    /// A user namespace called `sightingdb` must not land in the internal file.
    #[test]
    fn a_user_namespace_cannot_claim_the_internal_file() {
        let internal = shard_file(Path::new("/tmp"), INTERNAL_SHARD);
        let user = shard_file(Path::new("/tmp"), shard_of("sightingdb/values"));

        assert_ne!(internal, user);
        assert!(
            user.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("sightingdb-"),
            "{}",
            user.display()
        );
    }

    /// Namespaces arrive from URLs, so a shard name must never be able to
    /// steer the write out of the directory.
    #[test]
    fn a_hostile_namespace_cannot_escape_the_directory() {
        let dbdir = Path::new("/var/lib/sighting");
        for hostile in [
            "../../etc/cron.d/x",
            "..",
            "/etc/passwd",
            "a/../../b",
            "with space",
            "semi;colon",
        ] {
            let path = shard_file(dbdir, shard_of(hostile));
            assert_eq!(
                path.parent(),
                Some(dbdir),
                "{hostile:?} escaped to {}",
                path.display()
            );
            let name = path.file_name().unwrap().to_string_lossy();
            assert!(!name.contains('/'), "{hostile:?} produced {name}");
        }
    }

    /// `MyOrg` and `myorg` are one file on a case-insensitive filesystem, so
    /// the hash suffix has to keep them apart.
    #[test]
    fn shards_differing_only_in_case_get_different_files() {
        let dbdir = Path::new("/tmp");
        assert_ne!(shard_file(dbdir, "MyOrg"), shard_file(dbdir, "myorg"));
    }

    #[test]
    fn a_shard_file_is_still_recognisable() {
        let name = shard_file(Path::new("/tmp"), "myorg")
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        assert!(name.starts_with("myorg-"), "{name}");
        assert!(name.ends_with(SHARD_SUFFIX), "{name}");
    }

    // -- round trip --------------------------------------------------------

    /// Consensus and API keys live in the internal shard, so it has to be
    /// written and read back like any other.
    #[test]
    fn internal_state_round_trips_through_the_main_file() {
        let dir = TempDir::new("internal");
        let db = Database::new();
        db.write("myorg/a", "1.2.3.4", at(100), consensus());
        db.write("myorg/b", "1.2.3.4", at(100), consensus());

        save(&db, &dir.0, default_level(), true).unwrap();
        assert!(dir.0.join("sightingdb.json.zst").exists());

        let restored =
            Database::from_snapshot(load(&dir.0).unwrap().unwrap(), DatabasePolicy::default());
        // `_all` came back, so consensus survived the split.
        assert_eq!(restored.count(crate::db::ALL_NAMESPACE, "1.2.3.4"), 2);
    }

    #[test]
    fn a_database_survives_a_save_and_load() {
        let dir = TempDir::new("roundtrip");
        let db = Database::new();
        db.write("myorg/thisone", "1.2.3.4", at(1_600_000_000), consensus());
        db.write("myorg/other", "5.6.7.8", at(1_600_000_000), consensus());
        db.write("elsewhere/ns", "9.9.9.9", at(1_600_000_000), consensus());

        save(&db, &dir.0, default_level(), true).unwrap();
        let restored =
            Database::from_snapshot(load(&dir.0).unwrap().unwrap(), DatabasePolicy::default());

        assert_eq!(restored.count("myorg/thisone", "1.2.3.4"), 1);
        assert_eq!(restored.count("myorg/other", "5.6.7.8"), 1);
        assert_eq!(restored.count("elsewhere/ns", "9.9.9.9"), 1);
    }

    #[test]
    fn namespaces_are_split_into_a_file_per_shard() {
        let dir = TempDir::new("split");
        let db = Database::default();
        db.write("myorg/a", "v", at(100), WriteOpts::default());
        db.write("myorg/b", "v", at(100), WriteOpts::default());
        db.write("other/c", "v", at(100), WriteOpts::default());

        save(&db, &dir.0, default_level(), true).unwrap();

        let files: Vec<String> = fs::read_dir(&dir.0)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(SHARD_SUFFIX))
            .collect();

        assert_eq!(files.len(), 2, "{files:?}");
        assert!(files.iter().any(|n| n.starts_with("myorg-")), "{files:?}");
        assert!(files.iter().any(|n| n.starts_with("other-")), "{files:?}");
        // Nothing internal was written, so no sightingdb file either.
        assert!(
            !files.iter().any(|n| n == "sightingdb.json.zst"),
            "{files:?}"
        );
    }

    #[test]
    fn the_files_are_actually_compressed() {
        let dir = TempDir::new("zstd");
        let db = Database::default();
        for i in 0..2000 {
            db.write(
                "bulk/ns",
                &format!("10.0.0.{i}"),
                at(100),
                WriteOpts::default(),
            );
        }
        save(&db, &dir.0, default_level(), true).unwrap();

        let path = shard_file(&dir.0, "bulk");
        let compressed = fs::metadata(&path).unwrap().len();
        // Not a ratio assertion, just that it is not plain JSON.
        let head = fs::read(&path).unwrap();
        assert_eq!(&head[..4], &[0x28, 0xB5, 0x2F, 0xFD], "zstd magic missing");
        assert!(compressed > 0);
    }

    // -- incremental -------------------------------------------------------

    /// The point of sharding: an unchanged shard is not rewritten.
    #[test]
    fn only_changed_shards_are_written() {
        let dir = TempDir::new("incremental");
        let db = Database::default();
        db.write("alpha/ns", "v", at(100), WriteOpts::default());
        db.write("beta/ns", "v", at(100), WriteOpts::default());

        let first = save(&db, &dir.0, default_level(), false).unwrap();
        assert_eq!(first.shards_written, 2);

        // Nothing touched since.
        let second = save(&db, &dir.0, default_level(), false).unwrap();
        assert_eq!(second.shards_written, 0);
        assert_eq!(second.shards_skipped, 2);

        // One shard touched.
        db.write("alpha/ns", "another", at(200), WriteOpts::default());
        let third = save(&db, &dir.0, default_level(), false).unwrap();
        assert_eq!(third.shards_written, 1);
        assert_eq!(third.shards_skipped, 1);
    }

    #[test]
    fn saving_everything_ignores_the_dirty_set() {
        let dir = TempDir::new("saveall");
        let db = Database::default();
        db.write("alpha/ns", "v", at(100), WriteOpts::default());
        save(&db, &dir.0, default_level(), false).unwrap();

        let forced = save(&db, &dir.0, default_level(), true).unwrap();
        assert_eq!(forced.shards_written, 1);
    }

    #[test]
    fn a_deleted_namespace_is_gone_after_the_next_save() {
        let dir = TempDir::new("deleted");
        let db = Database::default();
        db.write("gone/ns", "v", at(100), WriteOpts::default());
        db.write("stays/ns", "v", at(100), WriteOpts::default());
        save(&db, &dir.0, default_level(), true).unwrap();
        assert!(shard_file(&dir.0, "gone").exists());

        db.delete("gone/ns");
        save(&db, &dir.0, default_level(), false).unwrap();

        assert!(!shard_file(&dir.0, "gone").exists());
        let restored =
            Database::from_snapshot(load(&dir.0).unwrap().unwrap(), DatabasePolicy::default());
        assert!(!restored.namespace_exists("gone/ns"));
        assert!(restored.namespace_exists("stays/ns"));
    }

    // -- failure and migration ---------------------------------------------

    #[test]
    fn loading_from_an_empty_directory_is_not_an_error() {
        let dir = TempDir::new("empty");
        assert!(load(&dir.0).unwrap().is_none());
    }

    /// An install upgrading from the single-file format must keep its data.
    #[test]
    fn a_single_file_snapshot_is_still_read() {
        let dir = TempDir::new("legacy");
        let db = Database::default();
        db.write("old/ns", "v", at(100), consensus());
        let json = serde_json::to_string(&db.snapshot()).unwrap();
        fs::write(dir.0.join(LEGACY_SNAPSHOT), json).unwrap();

        let restored =
            Database::from_snapshot(load(&dir.0).unwrap().unwrap(), DatabasePolicy::default());
        assert_eq!(restored.count("old/ns", "v"), 1);
    }

    #[test]
    fn a_corrupt_shard_names_the_file() {
        let dir = TempDir::new("corrupt");
        fs::write(shard_file(&dir.0, "broken"), b"not zstd").unwrap();

        let err = load(&dir.0).unwrap_err().to_string();
        assert!(err.contains("broken-"), "{err}");
    }

    #[test]
    fn saving_twice_leaves_no_temporary_files() {
        let dir = TempDir::new("tmpfile");
        let db = Database::default();
        db.write("ns/a", "v", at(100), WriteOpts::default());
        save(&db, &dir.0, default_level(), true).unwrap();
        save(&db, &dir.0, default_level(), true).unwrap();

        let leftovers: Vec<String> = fs::read_dir(&dir.0)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "left behind {leftovers:?}");
    }
}

#[cfg(test)]
mod scale {
    use super::tests::TempDir;
    use super::*;
    use crate::db::{Database, WriteOpts};
    use chrono::Utc;
    use std::time::Instant;

    /// Not a correctness test: it reports what a snapshot costs as the database
    /// grows, which is the number that decides whether this backend is enough.
    #[test]
    #[ignore = "measurement, run with --ignored"]
    fn snapshot_cost_at_scale() {
        for values in [100_000usize, 500_000, 1_000_000] {
            let dir = TempDir::new(&format!("scale-{values}"));
            let db = Database::default();

            let start = Instant::now();
            for i in 0..values {
                db.write(
                    &format!("feeds/ns{}", i % 20),
                    // Genuinely distinct: an IPv4-shaped generator wraps at
                    // 65_536 and would measure overwriting, not growth.
                    &format!(
                        "{}.{}.{}.{}",
                        (i >> 24) & 255,
                        (i >> 16) & 255,
                        (i >> 8) & 255,
                        i & 255
                    ),
                    Utc::now(),
                    WriteOpts {
                        consensus: true,
                        ttl: None,
                    },
                );
            }
            let ingest = start.elapsed();

            let start = Instant::now();
            let report = save(&db, &dir.0, default_level(), true).unwrap();
            let write = start.elapsed();

            let start = Instant::now();
            let loaded = load(&dir.0).unwrap().unwrap();
            let parse = start.elapsed();
            let restored = Database::from_snapshot(loaded, Default::default());
            assert!(restored.namespace_count() > 0);

            // The case sharding exists for: one shard touched since the last
            // save, which is what a periodic snapshot normally faces.
            db.write("busy/ns", "one-more", Utc::now(), WriteOpts::default());
            let start = Instant::now();
            let incremental = save(&db, &dir.0, default_level(), false).unwrap();
            let touch = start.elapsed();

            println!(
                "{values:>9} values | full save {:>6.2}s {:>6.1} MB in {} shard(s) | \
                 restore {:>6.2}s | after one write: {:>6.3}s ({} written, {} skipped)",
                write.as_secs_f64(),
                report.bytes as f64 / 1_048_576.0,
                report.shards_written,
                parse.as_secs_f64(),
                touch.as_secs_f64(),
                incremental.shards_written,
                incremental.shards_skipped,
            );
            let _ = ingest;
        }
    }
}
