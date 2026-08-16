//! TLS setup, and generating a self-signed certificate to get started with.
//!
//! Serving HTTPS is the default, which means a fresh checkout cannot start
//! until a certificate exists. Rather than leaving that as an OpenSSL error
//! about `fopen`, missing files are reported plainly and `--install-selfsigned-keys`
//! produces a usable pair.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::ssl::{SslAcceptor, SslAcceptorBuilder, SslFiletype, SslMethod};
use openssl::x509::extension::{BasicConstraints, KeyUsage, SubjectAlternativeName};
use openssl::x509::{X509, X509NameBuilder};

use crate::config::TlsSettings;

/// How long a generated certificate lasts. Long enough to be useful, short
/// enough that nobody mistakes it for something to run in production.
const VALID_DAYS: u32 = 365;

pub fn acceptor(tls: &TlsSettings) -> Result<SslAcceptorBuilder> {
    // Checked up front so the failure names the file and the remedy, instead
    // of surfacing OpenSSL's own message about being unable to open it.
    for (what, path) in [("certificate", &tls.cert), ("key", &tls.key)] {
        if !path.exists() {
            bail!(
                "TLS {what} {} does not exist.\n\
                 Run `sightingdb --install-selfsigned-keys` to generate a self-signed pair for \
                 testing, point ssl_cert/ssl_key at your own, or set ssl = false in [daemon] to \
                 serve plain HTTP.",
                path.display()
            );
        }
    }

    let mut builder =
        SslAcceptor::mozilla_intermediate(SslMethod::tls()).context("creating the TLS acceptor")?;
    builder
        .set_private_key_file(&tls.key, SslFiletype::PEM)
        .with_context(|| format!("reading TLS key {}", tls.key.display()))?;
    builder
        .set_certificate_chain_file(&tls.cert)
        .with_context(|| format!("reading TLS certificate {}", tls.cert.display()))?;
    Ok(builder)
}

/// Write a self-signed certificate and key at the configured paths.
///
/// Existing files are never overwritten: replacing a real certificate because
/// someone repeated a command would be much worse than refusing.
pub fn install_self_signed(tls: &TlsSettings) -> Result<()> {
    for path in [&tls.cert, &tls.key] {
        if path.exists() {
            bail!(
                "{} already exists. Remove it first if you really mean to replace it.",
                path.display()
            );
        }
    }

    let (certificate, key) = generate()?;

    write_private(&tls.key, &key)?;
    if let Some(parent) = tls.cert.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    fs::write(&tls.cert, &certificate)
        .with_context(|| format!("writing {}", tls.cert.display()))?;

    log::info!("Wrote a self-signed certificate to {}", tls.cert.display());
    log::info!("Wrote its private key to {}", tls.key.display());
    log::warn!(
        "This certificate is self-signed and valid for {VALID_DAYS} days. Clients will need to \
         skip verification (curl -k). Use a real certificate for anything that matters."
    );
    Ok(())
}

/// PEM certificate and PKCS#8 key for `localhost`.
fn generate() -> Result<(Vec<u8>, Vec<u8>)> {
    let rsa = Rsa::generate(2048).context("generating an RSA key")?;
    let key = PKey::from_rsa(rsa).context("wrapping the RSA key")?;

    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_text("CN", "localhost")?;
    name.append_entry_by_text("O", "SightingDB self-signed")?;
    let name = name.build();

    let mut builder = X509::builder()?;
    builder.set_version(2)?; // X509 v3
    builder.set_subject_name(&name)?;
    // Self-signed: the issuer is the subject.
    builder.set_issuer_name(&name)?;
    builder.set_pubkey(&key)?;

    let mut serial = BigNum::new()?;
    serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
    let serial = serial.to_asn1_integer()?;
    builder.set_serial_number(&serial)?;

    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(VALID_DAYS)?;
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;

    builder.append_extension(BasicConstraints::new().critical().build()?)?;
    builder.append_extension(
        KeyUsage::new()
            .critical()
            .digital_signature()
            .key_encipherment()
            .build()?,
    )?;
    // Modern clients ignore CN and require a SAN, so both spellings of
    // localhost go in.
    let san = SubjectAlternativeName::new()
        .dns("localhost")
        .ip("127.0.0.1")
        .ip("::1")
        .build(&builder.x509v3_context(None, None))?;
    builder.append_extension(san)?;

    builder.sign(&key, MessageDigest::sha256())?;
    let certificate = builder.build();

    Ok((
        certificate.to_pem().context("encoding the certificate")?,
        key.private_key_to_pem_pkcs8()
            .context("encoding the private key")?,
    ))
}

/// Write a private key, readable only by its owner.
fn write_private(path: &Path, contents: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        // Created 0600 from the start, rather than written world-readable and
        // tightened afterwards.
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("creating {}", path.display()))?;
        file.write_all(contents)
            .with_context(|| format!("writing {}", path.display()))?;
    }
    #[cfg(not(unix))]
    fs::write(path, contents).with_context(|| format!("writing {}", path.display()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!("sightingdb-tls-{tag}"));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            TempDir(path)
        }

        fn settings(&self) -> TlsSettings {
            TlsSettings {
                cert: self.0.join("ssl/cert.pem"),
                key: self.0.join("ssl/key.pem"),
            }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_generated_pair_is_usable_by_the_acceptor() {
        let dir = TempDir::new("generate");
        let tls = dir.settings();

        install_self_signed(&tls).unwrap();

        assert!(tls.cert.exists() && tls.key.exists());
        // The real test: OpenSSL accepts it as a server identity.
        acceptor(&tls).unwrap();
    }

    #[test]
    fn the_certificate_names_localhost() {
        let dir = TempDir::new("san");
        let tls = dir.settings();
        install_self_signed(&tls).unwrap();

        let pem = fs::read(&tls.cert).unwrap();
        let parsed = X509::from_pem(&pem).unwrap();

        let cn = parsed
            .subject_name()
            .entries_by_nid(openssl::nid::Nid::COMMONNAME)
            .next()
            .unwrap()
            .data()
            .to_string()
            .unwrap();
        assert_eq!(cn, "localhost");
        // Modern clients require a SAN; a CN alone would be rejected.
        assert!(parsed.subject_alt_names().is_some());
    }

    #[test]
    fn an_existing_file_is_never_replaced() {
        let dir = TempDir::new("noclobber");
        let tls = dir.settings();
        install_self_signed(&tls).unwrap();
        let original = fs::read(&tls.cert).unwrap();

        let err = install_self_signed(&tls).unwrap_err().to_string();

        assert!(err.contains("already exists"), "{err}");
        assert_eq!(fs::read(&tls.cert).unwrap(), original);
    }

    #[cfg(unix)]
    #[test]
    fn the_private_key_is_not_world_readable() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new("perms");
        let tls = dir.settings();
        install_self_signed(&tls).unwrap();

        let mode = fs::metadata(&tls.key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "key mode was {mode:o}");
    }

    /// The first-run failure has to say what to do about it, not surface
    /// OpenSSL's message about being unable to open a file.
    #[test]
    fn a_missing_certificate_explains_itself() {
        let dir = TempDir::new("missing");
        let err = match acceptor(&dir.settings()) {
            Ok(_) => panic!("a missing certificate should not have produced an acceptor"),
            Err(e) => e.to_string(),
        };

        assert!(err.contains("does not exist"), "{err}");
        assert!(err.contains("--install-selfsigned-keys"), "{err}");
        assert!(err.contains("ssl = false"), "{err}");
    }
}
