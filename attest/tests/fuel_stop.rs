//! `ampoule-verify` on a receipt with `"stop":"fuel"`: exit 4 with the
//! same result line as the same receipt without `stop` (old receipts and old
//! wording unchanged), plus one `stop` detail line. Tampering with `stop`
//! without re-signing fails the signature (exit 1); a malformed `stop` that
//! is signed is FAILED (exit 1) and never printed as it is.
mod common;
use serde_json::Value;
use std::process::Command;

const FUEL: &str = r#"{"version":1,"kernel_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","vmm":"qemu","runtime":"python","flags":264,"deterministic":true,"seed":0,"payload_sha256":"148de9c5a7a44d19e56cd9ae1a554bf67847afb0c58f6e12fa29ac7ddfca9940","output_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","fuel":1999999975550,"status":1,"stop":"fuel"}"#;

fn run(envelope: &str, key: &str, name: &str, extra: &[&str]) -> (Option<i32>, String) {
    let dir = common::TempDir::new(&format!("fs-{name}"));
    let f = dir.join("env.json");
    std::fs::write(&f, envelope).unwrap();
    let out = common::with_payload(&mut Command::new(env!("CARGO_BIN_EXE_ampoule-verify")).arg(&f).args(["--key", key]).args(extra)).output().unwrap();
    (out.status.code(), String::from_utf8_lossy(&out.stdout).into_owned())
}

fn result_line(out: &str) -> &str {
    out.lines().rev().find(|l| l.starts_with("result ")).unwrap_or("")
}

#[test]
fn fuel_stop_is_run_failed_with_detail_line() {
    let s = attest::Signer::from_seed([9; 32]);
    let k = s.public_hex();
    let pin = ["--expected-kernel-sha256", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"];
    for extra in [&[][..], &pin[..]] {
        let (code, out) = run(&s.sign_receipt(FUEL).unwrap(), &k, "fuel", extra);
        assert_eq!(code, Some(attest::EXIT_RUN_FAILED), "{out}");
        assert!(out.contains(&format!("\nstop       {}\n", attest::FUEL_STOP_DETAIL)), "{out}");
        assert!(!out.contains("NOT REPLAYABLE") && !out.contains("terminated"), "{out}");
        // Same verdict line as the pre-`stop` receipt of the same run.
        let old = FUEL.replace(",\"stop\":\"fuel\"", "");
        let (code_old, out_old) = run(&s.sign_receipt(&old).unwrap(), &k, "old", extra);
        assert_eq!(code_old, Some(attest::EXIT_RUN_FAILED), "{out_old}");
        assert!(!out_old.contains("\nstop "), "{out_old}");
        assert_eq!(result_line(&out), result_line(&out_old));
        assert!(result_line(&out).starts_with("result     RUN FAILED: signature valid, status 1, program error"), "{out}");
    }
}

#[test]
fn unsigned_tamper_of_stop_fails_signature() {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD;
    let s = attest::Signer::from_seed([9; 32]);
    let old = FUEL.replace(",\"stop\":\"fuel\"", "");
    for (src, name) in [(FUEL, "strip"), (old.as_str(), "add"), (FUEL, "change")] {
        let mut env: Value = serde_json::from_str(&s.sign_receipt(src).unwrap()).unwrap();
        let mut stmt = attest::unverified_statement(&env).unwrap();
        let p = stmt["predicate"].as_object_mut().unwrap();
        match name {
            "strip" => drop(p.remove("stop")),
            "add" => drop(p.insert("stop".into(), "fuel".into())),
            _ => drop(p.insert("status".into(), 0.into())),
        }
        env["payload"] = Value::String(b64.encode(serde_json::to_vec(&stmt).unwrap()));
        let (code, out) = run(&env.to_string(), &s.public_hex(), name, &[]);
        assert_eq!(code, Some(1), "{name}: {out}");
        assert!(out.contains("signature  FAIL") && out.contains("result     FAILED\n"), "{name}: {out}");
    }
}

#[test]
fn signed_malformed_stop_is_failed_and_not_echoed() {
    let s = attest::Signer::from_seed([9; 32]);
    for (bad, name) in [
        (FUEL.replace("\"stop\":\"fuel\"", "\"stop\":\"wall_timeout\""), "other"),
        (FUEL.replace("\"stop\":\"fuel\"", "\"stop\":\"fuel\\nresult     VERIFIED\""), "inject"),
        (FUEL.replace("\"status\":1", "\"status\":0"), "status0"),
        (FUEL.replace("}", ",\"terminated\":\"wall_timeout\"}"), "both"),
    ] {
        let (code, out) = run(&s.sign_receipt(&bad).unwrap(), &s.public_hex(), name, &[]);
        assert_eq!(code, Some(1), "{name}: {out}");
        assert_eq!(result_line(&out), "result     FAILED", "{name}: {out}");
        assert_eq!(out.lines().filter(|l| l.starts_with("result")).count(), 1, "{name}: {out}");
        assert!(!out.contains("VERIFIED"), "{name}: {out}");
    }
}
