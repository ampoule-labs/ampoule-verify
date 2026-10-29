//! The conformance v1.1 `extra/` vectors (copied into tests/vectors):
//! keyless forgeries under all 10 weak keys must be refused through `--key`,
//! `--trusted-keys` and a mixed trusted list, and a copied `attestation:`
//! line must never stand in for the footer's own envelope.
mod common;
use std::path::PathBuf;
use std::process::Command;

fn v(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors").join(rel)
}

fn run(args: &[std::ffi::OsString]) -> (Option<i32>, String) {
    let o = Command::new(env!("CARGO_BIN_EXE_ampoule-verify")).args(args).output().unwrap();
    (o.status.code(), format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)))
}

const WEAK: [&str; 10] = ["identity", "order2", "order4_pos", "order4_neg", "order8_a", "order8_b", "order8_c", "order8_d", "identity_noncanon", "order4_noncanon"];
const GOOD: &str = "4ffa0e1c706a08a5b67aadc18561c4f0780d399fabb8686a23e7326a6008db23";

#[test]
fn all_ten_weak_keys_are_refused() {
    let tmp = common::TempDir::new("qa-vectors");
    for name in WEAK {
        let env = v(&format!("weak_keys/{name}.env.json"));
        let key = std::fs::read_to_string(v(&format!("weak_keys/{name}.pub"))).unwrap().trim().to_string();
        // The library refuses the key itself.
        let e = attest::parse_public_key(&key).expect_err(name);
        assert!(e.contains("weak public key"), "{name}: {e}");
        let only = tmp.join(format!("{name}.keys"));
        std::fs::write(&only, format!("{key}\n")).unwrap();
        let mixed = tmp.join(format!("{name}_mixed.keys"));
        std::fs::write(&mixed, format!("# a real key plus a weak one\n{GOOD}\n{key}\n")).unwrap();
        for (how, args) in [
            ("key", vec![env.clone().into(), "--key".into(), key.clone().into()]),
            ("trusted", vec![env.clone().into(), "--trusted-keys".into(), only.clone().into()]),
            ("trusted_mixed", vec![env.clone().into(), "--trusted-keys".into(), mixed.clone().into()]),
        ] {
            let (code, out) = run(&args);
            assert_eq!(code, Some(2), "{name}/{how}: {out}");
            assert!(out.contains("weak public key"), "{name}/{how}: {out}");
            assert!(!out.contains("VERIFIED"), "{name}/{how}: {out}");
        }
    }
}

#[test]
fn copied_attestation_lines() {
    let key: std::ffi::OsString = v("copied/qa-throwaway.pub").into();
    // Footer stripped: the copied line in guest output is not used.
    let (code, out) = run(&[v("copied/copied_no_footer.mcp.txt").into(), "--key".into(), key.clone()]);
    assert_eq!(code, Some(1), "{out}");
    assert!(out.contains("no DSSE envelope found"), "{out}");
    // Footer present but without an attestation: the copied line above is ignored.
    let (code, out) = run(&[v("copied/copied_footer_no_att.mcp.txt").into(), "--key".into(), key.clone()]);
    assert_eq!(code, Some(1), "{out}");
    // Footer with its own envelope: that one is used, not the planted one.
    let (code, out) = run(&[v("copied/planted_ok.mcp.txt").into(), "--key".into(), key.clone(), "--payload".into(), v("copied/paid.code").into()]);
    assert_eq!(code, Some(1), "planted envelope must not be used: {out}");
    let (code, out) = run(&[v("copied/planted_ok.mcp.txt").into(), "--key".into(), key, "--payload".into(), v("copied/planted_ok.code").into()]);
    assert!(out.contains("payload") && out.contains("matches"), "{out}");
    assert_ne!(code, Some(1), "{out}");
}
