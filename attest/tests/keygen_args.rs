//! `ampoule-verify keygen --help` wrote a private key to a file named
//! `--help`. Now -h/--help print usage (exit 0) and any other argument that
//! starts with `-` is a usage error (exit 2); neither creates any file.
mod common;
use std::process::Command;

/// Run `ampoule-verify` in an empty dir, with HOME and AMPOULE_SIGNING_KEY
/// pointing inside it so a default-path key could only land there.
fn run(d: &common::TempDir, args: &[&str]) -> (Option<i32>, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_ampoule-verify"))
        .args(args)
        .current_dir(d.join("cwd"))
        .env("HOME", d.join("home"))
        .env("AMPOULE_SIGNING_KEY", d.join("home/default.key"))
        .output()
        .unwrap();
    (out.status.code(), String::from_utf8_lossy(&out.stdout).into(), String::from_utf8_lossy(&out.stderr).into())
}

fn setup(name: &str) -> common::TempDir {
    let d = common::TempDir::new(&format!("keygen73-{name}"));
    std::fs::create_dir_all(d.join("cwd")).unwrap();
    std::fs::create_dir_all(d.join("home")).unwrap();
    d
}

/// Every file under the temp dir (there must be none).
fn files(d: &common::TempDir) -> Vec<String> {
    let mut v = Vec::new();
    for sub in ["cwd", "home"] {
        for e in std::fs::read_dir(d.join(sub)).unwrap() {
            v.push(format!("{sub}/{}", e.unwrap().file_name().to_string_lossy()));
        }
    }
    v
}

#[test]
fn help_prints_usage_and_writes_nothing() {
    for cmd in ["keygen", "pubkey"] {
        for h in ["--help", "-h"] {
            let d = setup(&format!("help-{cmd}{h}"));
            let (rc, out, err) = run(&d, &[cmd, h]);
            assert_eq!(rc, Some(0), "{cmd} {h}: {err}");
            assert!(out.contains("usage: ampoule-verify"), "{cmd} {h}: {out}");
            assert!(files(&d).is_empty(), "{cmd} {h} created {:?}", files(&d));
        }
    }
}

#[test]
fn dash_arguments_are_usage_errors_and_write_nothing() {
    for cmd in ["keygen", "pubkey"] {
        for a in ["--force", "-x", "-", "--", "--help=1", "--version"] {
            let d = setup(&format!("dash-{cmd}{a}"));
            let (rc, out, err) = run(&d, &[cmd, a]);
            assert_eq!(rc, Some(2), "{cmd} {a}: {out}{err}");
            assert!(err.contains("usage: ampoule-verify"), "{cmd} {a}: {err}");
            assert!(out.is_empty(), "{cmd} {a} printed {out:?}");
            assert!(files(&d).is_empty(), "{cmd} {a} created {:?}", files(&d));
        }
    }
}

#[test]
fn dash_after_a_keyfile_is_still_refused() {
    let d = setup("after");
    let (rc, _, err) = run(&d, &["keygen", "k.key", "--help=no"]);
    assert_eq!(rc, Some(2), "{err}");
    assert!(files(&d).is_empty(), "created {:?}", files(&d));
    let (rc, _, err) = run(&d, &["keygen", "a.key", "b.key"]);
    assert_eq!(rc, Some(2), "{err}");
    assert!(files(&d).is_empty(), "created {:?}", files(&d));
}

#[test]
fn plain_keyfile_still_works() {
    let d = setup("plain");
    let (rc, out, err) = run(&d, &["keygen", "k.key"]);
    assert_eq!(rc, Some(0), "{err}");
    assert_eq!(out.trim().len(), 64, "public key line expected");
    assert!(d.join("cwd/k.key").exists());
    let (rc, out2, _) = run(&d, &["pubkey", "k.key"]);
    assert_eq!(rc, Some(0));
    assert_eq!(out, out2);
}
