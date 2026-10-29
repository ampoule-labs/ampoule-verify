//! `ampoule-verify` on any receipt (Wasm or Python)
//! whose check would otherwise pass (exit 0) is a usage error (exit 2)
//! without `--payload`, with a `payload ... (not checked)` line and never
//! VERIFIED. Every other verdict keeps its code without --payload: 1 (bad
//! signature, a differing --output), 3, 4 and 5.
mod common;
use serde_json::json;
use std::process::Command;

const K: &str = "1111111111111111111111111111111111111111111111111111111111111111";

fn run(env: &str, extra: &[&str], tag: &str) -> (Option<i32>, String) {
    let d = common::TempDir::new(&format!("wasm73-{tag}"));
    let f = d.join("env.json");
    std::fs::write(&f, env).unwrap();
    let pf = d.join("payload.bin");
    std::fs::write(&pf, b"module+input").unwrap();
    let mut args: Vec<String> = extra.iter().map(|s| s.to_string()).collect();
    std::fs::write(d.join("good.out"), b"42\n").unwrap();
    std::fs::write(d.join("bad.out"), b"43\n").unwrap();
    for a in args.iter_mut() {
        match a.as_str() {
            "PAYLOAD" => *a = pf.to_string_lossy().into(),
            "OUTGOOD" => *a = d.join("good.out").to_string_lossy().into(),
            "OUTBAD" => *a = d.join("bad.out").to_string_lossy().into(),
            _ => {}
        }
    }
    let out = Command::new(env!("CARGO_BIN_EXE_ampoule-verify")).arg(&f).args(&args).output().unwrap();
    (out.status.code(), format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
}

fn signed(runtime: &str, flags: u64) -> (String, String) {
    let s = attest::Signer::from_seed([7; 32]);
    let r = json!({"version":1,"kernel_sha256":K,"vmm":"qemu","runtime":runtime,"flags":flags,"deterministic":true,"seed":7,
        "payload_sha256":attest::sha256_hex(b"module+input"),"output_sha256":attest::sha256_hex(b"42\n"),"fuel":5,"status":0});
    (s.sign_receipt(&r.to_string()).unwrap(), s.public_hex())
}

#[test]
fn wasm_without_payload_is_exit_2() {
    let (env, key) = signed("wasm", 0x102);
    let (rc, out) = run(&env, &["--key", &key, "--expected-kernel-sha256", K], "nopay");
    assert_eq!(rc, Some(2), "{out}");
    assert!(out.contains("--payload FILE is required") && out.contains("(not checked)"), "{out}");
    assert!(!out.contains("VERIFIED"), "{out}");
}

#[test]
fn wasm_with_payload_verifies() {
    let (env, key) = signed("wasm", 0x102);
    let (rc, out) = run(&env, &["--key", &key, "--expected-kernel-sha256", K, "--payload", "PAYLOAD"], "pay");
    assert_eq!(rc, Some(0), "{out}");
    assert!(out.contains("VERIFIED"), "{out}");
}

#[test]
fn python_without_payload_is_exit_2() {
    let (env, key) = signed("python", 0x108);
    let (rc, out) = run(&env, &["--key", &key, "--expected-kernel-sha256", K], "py");
    assert_eq!(rc, Some(2), "{out}");
    assert!(out.contains("payload    ") && out.contains("(not checked)") && out.contains("--payload FILE is required"), "{out}");
    assert!(!out.contains("VERIFIED"), "{out}");
}

#[test]
fn python_with_payload_verifies() {
    let (env, key) = signed("python", 0x108);
    let (rc, out) = run(&env, &["--key", &key, "--expected-kernel-sha256", K, "--payload", "PAYLOAD"], "pypay");
    assert_eq!(rc, Some(0), "{out}");
    assert!(out.contains("result     VERIFIED (payload, kernel checked; output not checked)"), "{out}");
}

#[test]
fn bad_signature_still_fails_first() {
    let other = attest::Signer::from_seed([8; 32]).public_hex();
    for rt in [("wasm", 0x102), ("python", 0x108)] {
        let (env, _) = signed(rt.0, rt.1);
        let (rc, out) = run(&env, &["--key", &other, "--expected-kernel-sha256", K], "badsig");
        assert_eq!(rc, Some(1), "{}: {out}", rt.0);
        assert!(!out.contains("--payload FILE is required"), "{out}");
    }
}

fn signed_with(runtime: &str, flags: u64, f: impl FnOnce(&mut serde_json::Value)) -> (String, String) {
    let s = attest::Signer::from_seed([7; 32]);
    let mut r = json!({"version":1,"kernel_sha256":K,"vmm":"qemu","runtime":runtime,"flags":flags,"deterministic":true,"seed":7,
        "payload_sha256":attest::sha256_hex(b"module+input"),"output_sha256":attest::sha256_hex(b"42\n"),"fuel":5,"status":0});
    f(&mut r);
    (s.sign_receipt(&r.to_string()).unwrap(), s.public_hex())
}

/// Every receipt state, with and without --payload, for Python and Wasm:
/// (state, receipt edit, extra args, exit with --payload, exit without).
#[test]
fn precedence_matrix() {
    let pin = ["--expected-kernel-sha256", K];
    let none: &[&str] = &[];
    type Edit = fn(&mut serde_json::Value);
    let rows: [(&str, Edit, &[&str], bool, i32, i32); 9] = [
        ("ok-pinned", |_| {}, &pin, false, 0, 2),
        ("ok-pinned-output-match", |_| {}, &["--expected-kernel-sha256", K, "--output", "OUTGOOD"], false, 0, 2),
        ("ok-unpinned", |_| {}, none, false, 5, 5),
        ("output-differs", |_| {}, &["--expected-kernel-sha256", K, "--output", "OUTBAD"], false, 1, 1),
        ("output-differs-unpinned", |_| {}, &["--output", "OUTBAD"], false, 1, 1),
        ("run-failed", |r| r["status"] = 1.into(), &pin, false, 4, 4),
        ("not-replayable", |r| r["terminated"] = "wall_timeout".into(), &pin, false, 3, 3),
        ("wrong-kernel", |r| r["kernel_sha256"] = "2".repeat(64).into(), &pin, false, 1, 1),
        ("bad-signature", |_| {}, &pin, true, 1, 1),
    ];
    for (rt, flags) in [("python", 0x108u64), ("wasm", 0x102)] {
        for (name, edit, extra, badsig, with_p, without_p) in rows {
            let (env, mut key) = signed_with(rt, flags, edit);
            if badsig {
                key = attest::Signer::from_seed([8; 32]).public_hex();
            }
            let mut args = vec!["--key", key.as_str()];
            args.extend_from_slice(extra);
            let (rc, out) = run(&env, &args, &format!("m-{rt}-{name}"));
            assert_eq!(rc, Some(without_p), "{rt} {name} without --payload: {out}");
            assert_eq!(out.contains("--payload FILE is required"), without_p == 2, "{rt} {name}: {out}");
            assert!(!out.contains("VERIFIED"), "{rt} {name}: {out}");
            args.extend_from_slice(&["--payload", "PAYLOAD"]);
            let (rc, out) = run(&env, &args, &format!("m-{rt}-{name}-p"));
            assert_eq!(rc, Some(with_p), "{rt} {name} with --payload: {out}");
            assert_eq!(out.contains("VERIFIED"), with_p == 0, "{rt} {name}: {out}");
        }
    }
}

/// The USAGE line names "payload not checked" once;
/// its scope lists only the other files.
#[test]
fn usage_line_says_payload_once() {
    let (env, key) = signed("python", 0x108);
    let (rc, out) = run(&env, &["--key", &key, "--expected-kernel-sha256", K], "l1a");
    assert_eq!(rc, Some(2), "{out}");
    assert!(out.contains("result     USAGE: payload not checked (kernel checked; output not checked); pass --payload FILE\n"), "{out}");
    assert_eq!(out.matches("payload not checked").count(), 1, "{out}");
    let (rc, out) = run(&env, &["--key", &key, "--expected-kernel-sha256", K, "--output", "OUTGOOD"], "l1b");
    assert_eq!(rc, Some(2), "{out}");
    assert!(out.contains("result     USAGE: payload not checked; pass --payload FILE\n"), "{out}");
}

/// --help shows --payload as optional in the
/// synopsis and says it is required for exit 0.
#[test]
fn help_marks_payload_required_for_exit_0() {
    let out = Command::new(env!("CARGO_BIN_EXE_ampoule-verify")).arg("--help").output().unwrap();
    let t = String::from_utf8_lossy(&out.stdout);
    assert!(t.contains("[--payload FILE]") && t.contains("--payload FILE is required for exit 0"), "{t}");
}
