//! `ampoule-verify` must fail closed on `"terminated": "wall_timeout"`:
//! a genuine timeout receipt, or a normal receipt with the field forged in
//! and re-signed, is never VERIFIED (exit 3); stripping or adding the field
//! without re-signing breaks the signature (exit 1).
mod common;
use serde_json::Value;
use std::process::Command;

const NORMAL: &str = r#"{"version":1,"kernel_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","vmm":"qemu","runtime":"python","flags":264,"deterministic":true,"seed":7,"payload_sha256":"148de9c5a7a44d19e56cd9ae1a554bf67847afb0c58f6e12fa29ac7ddfca9940","output_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","fuel":5,"status":0}"#;
const TIMEOUT: &str = r#"{"version":1,"kernel_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","vmm":"qemu","runtime":"python","flags":264,"deterministic":true,"seed":7,"payload_sha256":"148de9c5a7a44d19e56cd9ae1a554bf67847afb0c58f6e12fa29ac7ddfca9940","output_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","fuel":5,"status":1,"terminated":"wall_timeout"}"#;

fn run(envelope: &str, key: &str, name: &str) -> (Option<i32>, String) {
    let dir = common::TempDir::new(&format!("nr-{name}"));
    let f = dir.join("env.json");
    std::fs::write(&f, envelope).unwrap();
    let out = common::with_payload(&mut Command::new(env!("CARGO_BIN_EXE_ampoule-verify")).arg(&f).args(["--key", key])).output().unwrap();
    (out.status.code(), String::from_utf8_lossy(&out.stdout).into_owned())
}

#[test]
fn normal_receipt_verifies() {
    let s = attest::Signer::from_seed([9; 32]);
    let (code, out) = run(&s.sign_receipt(NORMAL).unwrap(), &s.public_hex(), "normal");
    // Unpinned kernel: exit 5 (INCOMPLETE), never 0.
    assert_eq!(code, Some(attest::EXIT_SCOPE_INCOMPLETE), "{out}");
    assert!(out.contains("result     INCOMPLETE: signature valid, kernel not pinned (payload checked; output, kernel not checked); pin it with --kernel or --expected-kernel-sha256\n"), "{out}");
}

#[test]
fn genuine_timeout_receipt_is_not_ok() {
    let s = attest::Signer::from_seed([9; 32]);
    let (code, out) = run(&s.sign_receipt(TIMEOUT).unwrap(), &s.public_hex(), "genuine");
    assert_eq!(code, Some(attest::EXIT_NOT_REPLAYABLE), "{out}");
    assert!(out.contains("NOT REPLAYABLE: signature valid, terminated=wall_timeout"), "{out}");
    assert!(!out.contains("result     VERIFIED (payload checked; output, kernel not checked)\n"), "{out}");
}

#[test]
fn forged_and_resigned_field_is_not_ok() {
    // A dishonest signer adds the field to a normal receipt to dodge replay.
    let mut r: Value = serde_json::from_str(NORMAL).unwrap();
    r["terminated"] = "wall_timeout".into();
    let s = attest::Signer::from_seed([9; 32]);
    let (code, out) = run(&s.sign_receipt(&r.to_string()).unwrap(), &s.public_hex(), "forged");
    assert_eq!(code, Some(attest::EXIT_NOT_REPLAYABLE), "{out}");
    assert!(out.contains("NOT REPLAYABLE"), "{out}");
}

#[test]
fn unsigned_tamper_of_field_fails_signature() {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD;
    let s = attest::Signer::from_seed([9; 32]);
    for (src, name) in [(TIMEOUT, "strip"), (NORMAL, "add")] {
        let mut env: Value = serde_json::from_str(&s.sign_receipt(src).unwrap()).unwrap();
        let mut stmt = attest::unverified_statement(&env).unwrap();
        let p = stmt["predicate"].as_object_mut().unwrap();
        if p.remove("terminated").is_none() {
            p.insert("terminated".into(), "wall_timeout".into());
        }
        env["payload"] = Value::String(b64.encode(serde_json::to_vec(&stmt).unwrap()));
        let (code, out) = run(&env.to_string(), &s.public_hex(), name);
        assert_eq!(code, Some(1), "{name}: {out}");
        assert!(out.contains("signature  FAIL"), "{name}: {out}");
    }
}

// --- v2 predicate: v1-only verifiers fail closed on new receipts; this
// verifier accepts v1 (without `terminated`) and v2, and rejects v1 receipts
// that carry `terminated`.

#[test]
fn legacy_v1_normal_receipt_verifies() {
    let s = attest::Signer::from_seed([9; 32]);
    let (code, out) = run(&s.sign_receipt_as(NORMAL, attest::PREDICATE_TYPE_V1).unwrap(), &s.public_hex(), "v1normal");
    // Unpinned kernel: exit 5 (INCOMPLETE), never 0.
    assert_eq!(code, Some(attest::EXIT_SCOPE_INCOMPLETE), "{out}");
    assert!(out.contains("result     INCOMPLETE: signature valid, kernel not pinned (payload checked; output, kernel not checked); pin it with --kernel or --expected-kernel-sha256\n"), "{out}");
}

#[test]
fn v1_receipt_with_terminated_is_rejected() {
    let s = attest::Signer::from_seed([9; 32]);
    let (code, out) = run(&s.sign_receipt_as(TIMEOUT, attest::PREDICATE_TYPE_V1).unwrap(), &s.public_hex(), "v1term");
    assert_eq!(code, Some(1), "{out}");
    assert!(!out.contains("VERIFIED"), "{out}");
}

#[test]
fn unknown_predicate_type_is_rejected() {
    let s = attest::Signer::from_seed([9; 32]);
    let (code, out) = run(&s.sign_receipt_as(NORMAL, "https://ampoule.dev/attestation/run/v3").unwrap(), &s.public_hex(), "v3");
    assert_eq!(code, Some(1), "{out}");
}

#[test]
fn new_timeout_receipt_is_v2() {
    let s = attest::Signer::from_seed([9; 32]);
    let env: Value = serde_json::from_str(&s.sign_receipt(TIMEOUT).unwrap()).unwrap();
    assert_eq!(attest::unverified_statement(&env).unwrap()["predicateType"], attest::PREDICATE_TYPE_V2);
}

#[test]
fn null_terminated_is_not_ok() {
    let r = NORMAL.replace("\"status\":0}", "\"status\":0,\"terminated\":null}");
    let s = attest::Signer::from_seed([9; 32]);
    let (code, out) = run(&s.sign_receipt(&r).unwrap(), &s.public_hex(), "null");
    assert_eq!(code, Some(attest::EXIT_NOT_REPLAYABLE), "{out}");
    assert!(out.contains("NOT REPLAYABLE: signature valid, terminated=null"), "{out}");
}

/// Re-sign a hand-written statement (as a dishonest key holder could).
fn sign_raw(s_seed: [u8; 32], body: &str) -> String {
    use base64::Engine;
    use ed25519_dalek::Signer as _;
    let b64 = base64::engine::general_purpose::STANDARD;
    let key = ed25519_dalek::SigningKey::from_bytes(&s_seed);
    let sig = key.sign(&attest::pae(attest::PAYLOAD_TYPE, body.as_bytes()));
    serde_json::json!({"payloadType": attest::PAYLOAD_TYPE, "payload": b64.encode(body), "signatures": [{"keyid": attest::keyid(&key.verifying_key()), "sig": b64.encode(sig.to_bytes())}]}).to_string()
}

#[test]
fn duplicate_keys_fail() {
    let s = attest::Signer::from_seed([9; 32]);
    let stmt = |pred: &str, pt: &str| format!(r#"{{"_type":"{}","subject":[{{"name":"output","digest":{{"sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}}}}],{pt}"predicate":{pred}}}"#, attest::STATEMENT_TYPE);
    let pt = format!(r#""predicateType":"{}","#, attest::PREDICATE_TYPE);
    let cases = [
        ("dupterm", stmt(&TIMEOUT.replace("}", r#","terminated":null}"#), &pt)),
        ("dupptype", stmt(NORMAL, &format!(r#""predicateType":"https://example.com/x",{pt}"#))),
        ("nested", stmt(NORMAL, &pt).replace(r#"{"sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}"#, r#"{"sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}"#)),
    ];
    for (name, body) in cases {
        let (code, out) = run(&sign_raw([9; 32], &body), &s.public_hex(), name);
        assert_eq!(code, Some(1), "{name}: {out}");
        assert!(out.contains("duplicate key"), "{name}: {out}");
    }
}

/// The signed `terminated` reason is free-form,
/// so a key holder could inject a forged `result     VERIFIED` line (after a
/// newline or CR), an ANSI sequence, or the bare word into an exit-3 run.
/// Only a plain `[a-z_]` token is printed; anything else, the empty string
/// included, prints as `terminated=non-standard`. Exit 3 either way, the
/// word VERIFIED never appears, and the result is a single line.
#[test]
fn injected_terminated_reason_cannot_forge_a_line() {
    let s = attest::Signer::from_seed([9; 32]);
    let pin = ["--expected-kernel-sha256", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"];
    let cases: [(&str, Value); 8] = [
        ("word", "VERIFIED".into()),
        ("newline", "wall_timeout\nresult     VERIFIED".into()),
        ("cr", "wall_timeout\rresult     VERIFIED (payload, kernel checked; output not checked)".into()),
        ("ansi", "\u{1b}[1A\u{1b}[2Kresult     VERIFIED".into()),
        ("obj", serde_json::json!({"why": "VERIFIED"})),
        ("empty", "".into()),
        ("space", "wall timeout".into()),
        ("number", 7.into()),
    ];
    for (name, reason) in cases {
        let mut r: Value = serde_json::from_str(TIMEOUT).unwrap();
        r["terminated"] = reason;
        let dir = common::TempDir::new(&format!("nr-inject-{name}"));
        let f = dir.join("env.json");
        std::fs::write(&f, s.sign_receipt(&r.to_string()).unwrap()).unwrap();
        let out = common::with_payload(&mut Command::new(env!("CARGO_BIN_EXE_ampoule-verify")).arg(&f).args(["--key", &s.public_hex()]).args(pin)).output().unwrap();
        let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        drop(dir);
        assert_eq!(out.status.code(), Some(attest::EXIT_NOT_REPLAYABLE), "{name}: {text}");
        assert!(!text.contains("VERIFIED"), "{name}: {text}");
        assert!(!text.contains('\r') && !text.contains('\u{1b}'), "{name}: {text:?}");
        let results: Vec<&str> = text.lines().filter(|l| l.starts_with("result")).collect();
        assert_eq!(results, ["result     NOT REPLAYABLE: signature valid, terminated=non-standard (payload, kernel checked; output not checked)"], "{name}: {text}");
    }
}

/// The plain reasons a signer really writes still print as they are.
#[test]
fn plain_terminated_reason_is_printed() {
    let s = attest::Signer::from_seed([9; 32]);
    let mut r: Value = serde_json::from_str(TIMEOUT).unwrap();
    r["terminated"] = "guest_watchdog".into();
    let (code, out) = run(&s.sign_receipt(&r.to_string()).unwrap(), &s.public_hex(), "plain");
    assert_eq!(code, Some(attest::EXIT_NOT_REPLAYABLE), "{out}");
    assert!(out.contains("result     NOT REPLAYABLE: signature valid, terminated=guest_watchdog (payload checked;"), "{out}");
}
