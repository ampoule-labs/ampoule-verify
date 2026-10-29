//! Helpers shared by attest's integration tests.
#![allow(dead_code)]

/// A fresh scratch dir `$TMPDIR/ampoule-<tag>-<pid>`, removed when dropped,
/// so also when the test fails or panics (previously every
/// `cargo test` run left `ampoule-hard-*` and `ampoule-nr-*` dirs behind).
/// The same guard as verify's tests. `AMPOULE_KEEP_TEST_DIRS=1` keeps it
/// for debugging and prints its path.
pub struct TempDir(std::path::PathBuf);

impl TempDir {
    pub fn new(tag: &str) -> TempDir {
        let d = std::env::temp_dir().join(format!("ampoule-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        TempDir(d)
    }
}

impl std::ops::Deref for TempDir {
    type Target = std::path::Path;
    fn deref(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        if std::env::var_os("AMPOULE_KEEP_TEST_DIRS").is_some_and(|v| v == "1") {
            eprintln!("kept {}", self.0.display());
        } else {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

/// The bytes the fixtures' `payload_sha256` is the digest of: since
/// ampoule-verify requires --payload, every fixture signs
/// `payload_sha256 = sha256("p")` and [`with_payload`] passes this file.
pub const PAYLOAD_SHA256: &str = "148de9c5a7a44d19e56cd9ae1a554bf67847afb0c58f6e12fa29ac7ddfca9940";

pub fn payload_file() -> std::path::PathBuf {
    let p = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("fixture-payload-p");
    if std::fs::read(&p).ok().as_deref() != Some(b"p") {
        let tmp = p.with_extension(format!("{}", std::process::id()));
        std::fs::write(&tmp, b"p").unwrap();
        std::fs::rename(&tmp, &p).unwrap();
    }
    p
}

/// Add `--payload <payload_file()>` unless the command already names a
/// --payload (a test of --payload itself).
pub fn with_payload(cmd: &mut std::process::Command) -> &mut std::process::Command {
    if !cmd.get_args().any(|a| a == "--payload") {
        cmd.arg("--payload").arg(payload_file());
    }
    cmd
}
