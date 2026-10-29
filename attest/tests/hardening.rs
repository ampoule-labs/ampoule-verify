//! Hardening behaviour of the `ampoule-verify` CLI: strict predicate
//! types, `kernel_sha256` required, missing files exit 2, DSSE multi-signature
//! and keyid handling, the scope of a VERIFIED, the status verdict (exit 4),
//! `--expected-kernel-sha256`, `--trusted-keys`, and output-cap notes.
mod common;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::process::Command;

const K: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const P: &str = common::PAYLOAD_SHA256;

fn receipt(out_sha: &str, status: u64) -> Value {
    json!({"version":1,"kernel_sha256":K,"vmm":"qemu","runtime":"python","flags":264,"deterministic":true,"seed":7,
           "payload_sha256":P,"output_sha256":out_sha,"fuel":5,"status":status})
}

fn dir(name: &str) -> common::TempDir {
    common::TempDir::new(&format!("hard-{name}"))
}

fn verify(env: &str, args: &[&str], name: &str) -> (Option<i32>, String) {
    // Its own dir, not dir(name): a test may hold dir(name) for its files.
    let d = dir(&format!("{name}-env"));
    let f = d.join("env.json");
    std::fs::write(&f, env).unwrap();
    let out = common::with_payload(&mut Command::new(env!("CARGO_BIN_EXE_ampoule-verify")).arg(&f).args(args)).output().unwrap();
    (out.status.code(), format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
}

fn signer(n: u8) -> attest::Signer {
    attest::Signer::from_seed([n; 32])
}

fn sign(s: &attest::Signer, r: &Value) -> String {
    s.sign_receipt(&r.to_string()).unwrap()
}

#[test]
fn verified_states_what_was_not_checked() {
    let s = signer(1);
    let out_bytes = b"42\n";
    let env = sign(&s, &receipt(&attest::sha256_hex(out_bytes), 0));
    let (code, out) = verify(&env, &["--key", &s.public_hex()], "scope0");
    assert_eq!(code, Some(attest::EXIT_SCOPE_INCOMPLETE), "{out}");
    assert!(out.contains("result     INCOMPLETE: signature valid, kernel not pinned (payload checked; output, kernel not checked); pin it with --kernel or --expected-kernel-sha256\n"), "{out}");
    let d = dir("scope1");
    std::fs::write(d.join("out"), out_bytes).unwrap();
    let o = d.join("out");
    let (code, out) = verify(&env, &["--key", &s.public_hex(), "--output", o.to_str().unwrap()], "scope1");
    assert_eq!(code, Some(attest::EXIT_SCOPE_INCOMPLETE), "{out}");
    assert!(out.contains("result     INCOMPLETE: signature valid, kernel not pinned (output, payload checked; kernel not checked); pin it with --kernel or --expected-kernel-sha256\n"), "{out}");
    let (code, out) = verify(&env, &["--key", &s.public_hex(), "--output", o.to_str().unwrap(), "--expected-kernel-sha256", &K.to_uppercase()], "scope2");
    assert_eq!(code, Some(0), "{out}");
    assert!(out.contains("result     VERIFIED\n"), "{out}");
}

#[test]
fn expected_kernel_sha256_pins_the_kernel() {
    let s = signer(1);
    let env = sign(&s, &receipt(&attest::sha256_hex(b""), 0));
    let other = "3".repeat(64);
    let (code, out) = verify(&env, &["--key", &s.public_hex(), "--expected-kernel-sha256", &other], "ek-bad");
    assert_eq!(code, Some(1), "{out}");
    assert!(out.contains("DIFFERS from --expected-kernel-sha256") && out.contains("result     FAILED"), "{out}");
    let (code, out) = verify(&env, &["--key", &s.public_hex(), "--expected-kernel-sha256", "abc"], "ek-short");
    assert_eq!(code, Some(2), "{out}");
    let (code, _) = verify(&env, &["--key", &s.public_hex(), "--expected-kernel-sha256", K, "--expected-kernel-sha256", K], "ek-twice");
    assert_eq!(code, Some(2));
    // A kernel file and the digest pin must both match.
    let d = dir("ek-file");
    std::fs::write(d.join("k"), b"not the kernel").unwrap();
    let (code, out) = verify(&env, &["--key", &s.public_hex(), "--kernel", d.join("k").to_str().unwrap(), "--expected-kernel-sha256", K], "ek-file");
    assert_eq!(code, Some(1), "{out}");
}

#[test]
fn trusted_keys_file_accepts_any_listed_key() {
    let (a, b, c) = (signer(1), signer(2), signer(3));
    let env = sign(&b, &receipt(&attest::sha256_hex(b""), 0));
    let d = dir("tk");
    let f = d.join("trusted");
    std::fs::write(&f, format!("# operators\n{}\n\n{}  # backup host\n", a.public_hex(), b.public_hex())).unwrap();
    let (code, out) = verify(&env, &["--trusted-keys", f.to_str().unwrap(), "--expected-kernel-sha256", K], "tk-ok");
    assert_eq!(code, Some(0), "{out}");
    assert!(out.contains("(trusted key 2 of 2)"), "{out}");
    let g = d.join("untrusted");
    std::fs::write(&g, format!("{}\n", c.public_hex())).unwrap();
    let (code, out) = verify(&env, &["--trusted-keys", g.to_str().unwrap()], "tk-no");
    assert_eq!(code, Some(1), "{out}");
    assert!(out.contains("no signature from any trusted key") || out.contains("no signature from this key"), "{out}");
    // --key and --trusted-keys combine.
    let (code, _) = verify(&env, &["--trusted-keys", g.to_str().unwrap(), "--key", &b.public_hex(), "--expected-kernel-sha256", K], "tk-mix");
    assert_eq!(code, Some(0));
    for (name, text) in [("tk-empty", "# nothing\n"), ("tk-junk", "not-a-key\n")] {
        let h = d.join(name);
        std::fs::write(&h, text).unwrap();
        let (code, out) = verify(&env, &["--trusted-keys", h.to_str().unwrap()], name);
        assert_eq!(code, Some(2), "{name}: {out}");
    }
    let (code, _) = verify(&env, &["--trusted-keys", "/nonexistent/trusted"], "tk-missing");
    assert_eq!(code, Some(2));
}

#[test]
fn missing_input_files_exit_2() {
    let s = signer(1);
    let env = sign(&s, &receipt(&attest::sha256_hex(b""), 0));
    for flag in ["--payload", "--output", "--kernel"] {
        let (code, out) = verify(&env, &["--key", &s.public_hex(), flag, "/nonexistent/file"], &format!("miss{flag}"));
        assert_eq!(code, Some(2), "{flag}: {out}");
        assert!(!out.contains("VERIFIED"), "{flag}: {out}");
    }
    let out = Command::new(env!("CARGO_BIN_EXE_ampoule-verify")).args(["/nonexistent/env.json", "--key", &s.public_hex()]).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn nonzero_status_has_its_own_verdict() {
    let s = signer(1);
    let (code, out) = verify(&sign(&s, &receipt(&attest::sha256_hex(b""), 1)), &["--key", &s.public_hex()], "status1");
    assert_eq!(code, Some(attest::EXIT_RUN_FAILED), "{out}");
    assert!(out.contains("result     RUN FAILED: signature valid, status 1, program error (payload checked; output, kernel not checked)"), "{out}");
    // One note prefix: every note line starts with `note (unsigned): `.
    assert!(out.contains("note (unsigned): the run itself reported status 1, program error:"), "{out}");
    assert!(out.lines().filter(|l| l.starts_with("note")).all(|l| l.starts_with("note (unsigned): ")), "{out}");
    assert!(!out.contains("result     VERIFIED\n") && !out.contains("result     VERIFIED ("), "{out}");
    // terminated outranks the status (a stopped run's status describes the stop).
    let mut r = receipt(&attest::sha256_hex(b""), 1);
    r["terminated"] = "wall_timeout".into();
    let (code, out) = verify(&sign(&s, &r), &["--key", &s.public_hex()], "status1-term");
    assert_eq!(code, Some(attest::EXIT_NOT_REPLAYABLE), "{out}");
    // A digest mismatch outranks both.
    let d = dir("status1-out");
    std::fs::write(d.join("o"), b"x").unwrap();
    let (code, _) = verify(&sign(&s, &receipt(&attest::sha256_hex(b""), 1)), &["--key", &s.public_hex(), "--output", d.join("o").to_str().unwrap()], "status1-out");
    assert_eq!(code, Some(1));
}

#[test]
fn strict_predicate_and_required_kernel() {
    let s = signer(1);
    let base = receipt(&attest::sha256_hex(b""), 0);
    let mutate: Vec<(&str, Box<dyn Fn(&mut Value)>)> = vec![
        ("no-kernel", Box::new(|r| { r.as_object_mut().unwrap().remove("kernel_sha256"); })),
        ("kernel-short", Box::new(|r| r["kernel_sha256"] = "aa".into())),
        ("kernel-upper", Box::new(|r| r["kernel_sha256"] = K.replace('1', "A").into())),
        ("version-2", Box::new(|r| r["version"] = 2.into())),
        ("version-str", Box::new(|r| r["version"] = "1".into())),
        ("version-float", Box::new(|r| r["version"] = json!(1.0))),
        ("vmm-kvm", Box::new(|r| r["vmm"] = "kvm".into())),
        ("runtime-ruby", Box::new(|r| r["runtime"] = "ruby".into())),
        ("det-int", Box::new(|r| r["deterministic"] = 1.into())),
        ("det-bit", Box::new(|r| r["flags"] = 8.into())),
        ("fuel-neg", Box::new(|r| r["fuel"] = json!(-1))),
        ("status-null", Box::new(|r| r["status"] = Value::Null)),
        ("seed-missing", Box::new(|r| { r.as_object_mut().unwrap().remove("seed"); })),
    ];
    for (name, m) in mutate {
        let mut r = base.clone();
        m(&mut r);
        let (code, out) = verify(&sign(&s, &r), &["--key", &s.public_hex()], name);
        assert_eq!(code, Some(1), "{name}: {out}");
        assert!(out.contains("predicate."), "{name}: {out}");
    }
    // The predicate field list is closed; an extra field is FAILED
    // (it used to be ignored, exit 0). See unknown_predicate_field_fails.
    let mut r = base.clone();
    r["note"] = "x".into();
    let (code, out) = verify(&sign(&s, &r), &["--key", &s.public_hex(), "--expected-kernel-sha256", K], "extra");
    assert_eq!(code, Some(1), "{out}");
    assert!(out.starts_with("note (unsigned): predicate has 1 unknown field (first: \"note\")"), "{out}");
}

/// A raw envelope with chosen signature entries over `body`.
fn envelope(body: &str, sigs: Vec<Value>) -> String {
    use base64::Engine;
    json!({"payloadType": attest::PAYLOAD_TYPE, "payload": base64::engine::general_purpose::STANDARD.encode(body), "signatures": sigs}).to_string()
}

fn sig_entry(seed: u8, body: &str, keyid: Option<&str>) -> Value {
    use base64::Engine;
    use ed25519_dalek::Signer as _;
    let k = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    let sig = base64::engine::general_purpose::STANDARD.encode(k.sign(&attest::pae(attest::PAYLOAD_TYPE, body.as_bytes())).to_bytes());
    match keyid {
        Some(id) => json!({"keyid": id, "sig": sig}),
        None => json!({"sig": sig}),
    }
}

#[test]
fn dsse_multi_signature_and_keyid_hint() {
    let good = signer(1);
    let body = serde_json::to_string(&attest::statement(&receipt(&attest::sha256_hex(b""), 0)).unwrap()).unwrap();
    let id = good.keyid().to_string();
    let other_id = signer(2).keyid().to_string();
    let bad = { let mut e = sig_entry(1, &body, Some(&id)); e["sig"] = sig_entry(1, "other", None)["sig"].clone(); e };
    let cases: Vec<(&str, Vec<Value>, i32)> = vec![
        ("bad-then-good", vec![bad.clone(), sig_entry(1, &body, Some(&id))], 0),
        ("other-then-good", vec![sig_entry(2, &body, Some(&other_id)), sig_entry(1, &body, Some(&id))], 0),
        ("keyid-missing", vec![sig_entry(1, &body, None)], 0),
        ("keyid-empty", vec![sig_entry(1, &body, Some(""))], 0),
        ("keyid-wrong", vec![sig_entry(1, &body, Some(&other_id))], 1),
        ("keyid-upper", vec![sig_entry(1, &body, Some(&id.to_uppercase()))], 1),
        ("only-bad", vec![bad], 1),
        ("empty", vec![], 1),
    ];
    for (name, sigs, want) in cases {
        let (code, out) = verify(&envelope(&body, sigs), &["--key", &good.public_hex(), "--expected-kernel-sha256", K], name);
        assert_eq!(code, Some(want), "{name}: {out}");
    }
}

#[test]
fn output_at_the_cap_is_flagged() {
    let s = signer(1);
    let big = vec![b'x'; attest::OUTPUT_CAP];
    let env = sign(&s, &receipt(&attest::sha256_hex(&big), 0));
    let d = dir("cap");
    std::fs::write(d.join("o"), &big).unwrap();
    let (code, out) = verify(&env, &["--key", &s.public_hex(), "--output", d.join("o").to_str().unwrap(), "--expected-kernel-sha256", K], "cap");
    assert_eq!(code, Some(0), "{out}");
    assert!(out.contains("note (unsigned): output is 65536 bytes, exactly the 64 KiB output cap"), "{out}");
    let small = "ok \u{FFFD}\n".as_bytes();
    let env = sign(&s, &receipt(&attest::sha256_hex(small), 0));
    std::fs::write(d.join("o2"), small).unwrap();
    let (code, out) = verify(&env, &["--key", &s.public_hex(), "--output", d.join("o2").to_str().unwrap(), "--expected-kernel-sha256", K], "fffd");
    assert_eq!(code, Some(0), "{out}");
    assert!(out.contains("output contains U+FFFD") && !out.contains("output cap"), "{out}");
}

/// L1: a forged envelope "signed" by the identity point (R = identity,
/// s = 0 satisfies lax Ed25519 for any message) must never verify: the weak
/// key is refused as `--key` and in `--trusted-keys` (exit 2, before any
/// verdict), and the forged signature does not verify under strict checks.
#[test]
fn identity_key_and_forged_signature_are_rejected() {
    use base64::Engine as _;
    const IDENTITY: &str = "0100000000000000000000000000000000000000000000000000000000000000";
    let stmt = attest::statement(&receipt(&attest::sha256_hex(b"forged\n"), 0)).unwrap();
    let body = serde_json::to_vec(&stmt).unwrap();
    let mut sig = [0u8; 64];
    sig[0] = 1;
    let b64 = base64::engine::general_purpose::STANDARD;
    let env = json!({"payloadType": attest::PAYLOAD_TYPE, "payload": b64.encode(&body),
                     "signatures": [{"keyid": "", "sig": b64.encode(sig)}]})
    .to_string();
    let (code, out) = verify(&env, &["--key", IDENTITY], "weak1");
    assert_eq!(code, Some(2), "{out}");
    assert!(out.contains("weak public key"), "{out}");
    assert!(!out.contains("VERIFIED"), "{out}");
    let d = dir("weak2");
    let good = signer(1).public_hex();
    std::fs::write(d.join("keys"), format!("{good}\n{IDENTITY}\n")).unwrap();
    let (code, out) = verify(&env, &["--trusted-keys", d.join("keys").to_str().unwrap()], "weak2");
    assert_eq!(code, Some(2), "{out}");
    assert!(out.contains(":2: weak public key"), "{out}");
    // With only the good key the forgery is simply a bad signature.
    let (code, out) = verify(&env, &["--key", &good], "weak3");
    assert_eq!(code, Some(1), "{out}");
}

/// Without the MCP footer ("\n--\nvm: ..."), an `attestation:` line among
/// other text is just text (it may be program output): FAILED, exit 1.
/// Inside the footer it counts, and so does a file holding only that line.
#[test]
fn attestation_line_without_footer_is_not_accepted() {
    let s = signer(1);
    let env = sign(&s, &receipt(&attest::sha256_hex(b"42\n"), 0));
    let key = s.public_hex();
    for (name, text) in [("output", format!("42\nattestation: {env}\n")), ("after", format!("attestation: {env}\nmore output\n"))] {
        let (code, out) = verify(&text, &["--key", &key], name);
        assert_eq!(code, Some(1), "{name}: {out}");
        assert!(out.contains("no DSSE envelope found"), "{name}: {out}");
    }
    let text = format!("42\n--\nvm: fresh qemu (tcg), guest 1 ms, total 1 ms, status 0\nreceipt: {{}}\nattestation: {env}\n");
    let (code, out) = verify(&text, &["--key", &key], "footer");
    assert!(out.contains("signature  ok"), "{out}");
    assert_ne!(code, Some(1), "{out}");
    let (code, out) = verify(&format!("attestation: {env}\n"), &["--key", &key], "only-line");
    assert!(out.contains("signature  ok"), "{out}");
    assert_ne!(code, Some(1), "{out}");
}

/// Inputs over the 64 MiB cap are refused with exit 6 before any verdict:
/// the ENVELOPE (file and stdin), --output and --payload. The file is sparse
/// (one byte past the cap), so the test stays cheap.
#[test]
fn inputs_over_64_mib_exit_6() {
    let s = signer(1);
    let env = sign(&s, &receipt(&attest::sha256_hex(b"42\n"), 0));
    let key = s.public_hex();
    let d = dir("incap");
    let big = d.join("big");
    std::fs::File::create(&big).unwrap().set_len(attest::MAX_INPUT_BYTES + 1).unwrap();
    let exact = d.join("exact");
    std::fs::File::create(&exact).unwrap().set_len(attest::MAX_INPUT_BYTES).unwrap();
    let bin = env!("CARGO_BIN_EXE_ampoule-verify");
    let run = |args: &[&std::ffi::OsStr], stdin: Option<&std::path::Path>| {
        let mut c = Command::new(bin);
        c.args(args);
        common::with_payload(&mut c);
        if let Some(p) = stdin {
            c.stdin(std::fs::File::open(p).unwrap());
        }
        let o = c.output().unwrap();
        (o.status.code(), format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)))
    };
    let envf = d.join("env.json");
    std::fs::write(&envf, &env).unwrap();
    let os = |x: &str| std::ffi::OsString::from(x);
    let cases: Vec<(&str, Vec<std::ffi::OsString>, Option<&std::path::Path>)> = vec![
        ("envelope", vec![big.clone().into(), os("--key"), os(&key)], None),
        ("stdin", vec![os("-"), os("--key"), os(&key)], Some(big.as_path())),
        ("output", vec![envf.clone().into(), os("--key"), os(&key), os("--output"), big.clone().into()], None),
        ("payload", vec![envf.clone().into(), os("--key"), os(&key), os("--payload"), big.clone().into()], None),
    ];
    for (name, args, stdin) in cases {
        let refs: Vec<&std::ffi::OsStr> = args.iter().map(|a| a.as_os_str()).collect();
        let (code, out) = run(&refs, stdin);
        assert_eq!(code, Some(attest::EXIT_INPUT_TOO_LARGE), "{name}: {out}");
        assert!(out.contains("larger than the 64 MiB input limit"), "{name}: {out}");
        // Its own word: FAILED is exit 1.
        assert!(out.contains("result     INPUT TOO LARGE: over the 64 MiB input limit; nothing checked\n"), "{name}: {out}");
        assert!(!out.contains("FAILED"), "{name}: {out}");
        assert!(!out.contains("VERIFIED"), "{name}: {out}");
    }
    // Exactly at the cap is read (and then simply does not match).
    let (code, out) = run(&[envf.as_os_str(), os("--key").as_os_str(), os(&key).as_os_str(), os("--output").as_os_str(), exact.as_os_str()], None);
    assert_eq!(code, Some(1), "{out}");
    assert!(out.contains("DIFFERS"), "{out}");
    let _ = std::fs::remove_file(&big);
    let _ = std::fs::remove_file(&exact);
}

/// Precedence 2 > 1 > 3 > 4 > 5 > 0 on the CLI: every combination of
/// pinned/unpinned with a normal, failed and not-replayable receipt, plus a
/// digest mismatch and a usage error on top.
#[test]
fn exit_code_precedence_combined_cases() {
    let s = signer(1);
    let key = s.public_hex();
    let ok = receipt(&attest::sha256_hex(b""), 0);
    let failed = receipt(&attest::sha256_hex(b""), 1);
    let mut stopped = receipt(&attest::sha256_hex(b""), 1);
    stopped["terminated"] = "wall_timeout".into();
    let d = dir("prec");
    std::fs::write(d.join("bad-out"), b"x").unwrap();
    let bad_out = d.join("bad-out");
    let bad_out = bad_out.to_str().unwrap();
    let pin: &[&str] = &["--expected-kernel-sha256", K];
    let wrong = "3".repeat(64);
    let cases: Vec<(&str, &Value, Vec<&str>, i32, &str)> = vec![
        ("ok-pinned", &ok, pin.to_vec(), 0, "result     VERIFIED (payload, kernel checked; output not checked)"),
        ("ok-unpinned", &ok, vec![], 5, "result     INCOMPLETE: signature valid, kernel not pinned (payload checked; output, kernel not checked)"),
        ("failed-pinned", &failed, pin.to_vec(), 4, "RUN FAILED: signature valid, status 1, program error (payload, kernel checked; output not checked)"),
        ("failed-unpinned", &failed, vec![], 4, "RUN FAILED: signature valid, status 1, program error (payload checked; output, kernel not checked)"),
        ("stopped-pinned", &stopped, pin.to_vec(), 3, "NOT REPLAYABLE: signature valid, terminated=wall_timeout"),
        ("stopped-unpinned", &stopped, vec![], 3, "NOT REPLAYABLE: signature valid, terminated=wall_timeout (payload checked; output, kernel not checked)"),
        ("ok-badout", &ok, vec!["--output", bad_out], 1, "result     FAILED"),
        ("failed-badout", &failed, vec!["--output", bad_out], 1, "result     FAILED"),
        ("stopped-badout", &stopped, vec!["--output", bad_out], 1, "result     FAILED"),
        ("stopped-badpin", &stopped, vec!["--expected-kernel-sha256", &wrong], 1, "result     FAILED"),
        ("stopped-usage", &stopped, vec!["--bogus"], 2, ""),
        ("failed-missing-file", &failed, vec!["--payload", "/nonexistent/p"], 2, ""),
    ];
    for (name, r, extra, want, line) in cases {
        let mut args = vec!["--key", key.as_str()];
        args.extend(extra);
        let (code, out) = verify(&sign(&s, r), &args, &format!("prec-{name}"));
        assert_eq!(code, Some(want), "{name}: {out}");
        assert!(out.contains(line), "{name}: {out}");
    }
}

#[test]
fn help_and_version_exit_0() {
    let bin = env!("CARGO_BIN_EXE_ampoule-verify");
    for a in ["--help", "-h"] {
        let o = Command::new(bin).arg(a).output().unwrap();
        let out = String::from_utf8_lossy(&o.stdout);
        assert_eq!(o.status.code(), Some(0), "{a}");
        assert!(out.contains("usage: ampoule-verify") && out.contains("5 INCOMPLETE (signature valid, kernel not pinned; not a pass)") && out.contains("precedence: 2 (and 6) > 1 > 3 > 4 > 5 > 0"), "{out}");
    }
    for a in ["--version", "-V"] {
        let o = Command::new(bin).arg(a).output().unwrap();
        assert_eq!(o.status.code(), Some(0), "{a}");
        assert!(String::from_utf8_lossy(&o.stdout).starts_with(&format!("ampoule-verify {}", env!("CARGO_PKG_VERSION"))));
        // A real version, not the 0.1.0 every build printed before the hardening release,
        // so a parser can tell the current wording from the old; same line format.
        assert_eq!(String::from_utf8_lossy(&o.stdout), format!("ampoule-verify 0.2.0 (predicate {})\n", attest::PREDICATE_TYPE), "{a}");
    }
    // A real usage error still exits 2, with the usage on stderr.
    let o = Command::new(bin).output().unwrap();
    assert_eq!(o.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&o.stderr).contains("usage: ampoule-verify"));
}

/// An unreadable or missing input file is exit 2 (usage / I-O),
/// deliberately (it says nothing about the receipt), and it outranks every
/// verdict, FAILED included (precedence 2 > 1 > 3 > 4 > 5 > 0): all files
/// are read before any verdict.
#[test]
fn unreadable_files_exit_2_and_outrank_failed() {
    let s = signer(1);
    let other = signer(2);
    let good = sign(&s, &receipt(&attest::sha256_hex(b""), 0));
    let d = dir("unreadable");
    let locked = d.join("locked");
    std::fs::write(&locked, b"x").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    }
    let unreadable = std::fs::read(&locked).is_err(); // false when run as root
    let wrong_key = other.public_hex();
    for flag in ["--output", "--payload", "--kernel", "--trusted-keys"] {
        // With a key that does not match (would be FAILED, exit 1) and a missing file.
        let mut args = vec!["--key", wrong_key.as_str(), flag, "/nonexistent/file"];
        if flag == "--trusted-keys" {
            args.drain(..2);
        }
        let (code, out) = verify(&good, &args, &format!("unr-missing{flag}"));
        assert_eq!(code, Some(2), "{flag}: {out}");
        assert!(!out.contains("result"), "{flag}: no verdict before the files are read: {out}");
        if unreadable {
            let p = locked.to_str().unwrap();
            let mut args = vec!["--key", wrong_key.as_str(), flag, p];
            if flag == "--trusted-keys" {
                args.drain(..2);
            }
            let (code, out) = verify(&good, &args, &format!("unr-locked{flag}"));
            assert_eq!(code, Some(2), "{flag} (permission denied): {out}");
        }
    }
}

/// The unsigned output notes are the same newline-terminated
/// `note (unsigned): ...` lines in every mode: with --output, and on a saved
/// MCP result without --output (from the output above the footer).
#[test]
fn output_notes_same_in_every_mode() {
    let s = signer(1);
    let body = "bad \u{FFFD}\n".as_bytes();
    let rc = receipt(&attest::sha256_hex(body), 0);
    let env = sign(&s, &rc);
    let lines = attest::output_note_lines(body);
    assert!(lines.starts_with(attest::NOTE_PREFIX) && lines.ends_with('\n'), "{lines}");
    let d = dir("notes");
    std::fs::write(d.join("o"), body).unwrap();
    let key = s.public_hex();
    let (_, with_output) = verify(&env, &["--key", &key, "--output", d.join("o").to_str().unwrap()], "notes-out");
    assert!(with_output.contains(&lines), "{with_output}");
    // A saved MCP result, the way the server writes it (notes after the attestation).
    let mcp = format!("{}\n--\nvm: fresh qemu (tcg), guest 1 ms, total 1 ms, status 0\nreceipt: {rc}\nattestation: {env}\n{lines}", String::from_utf8_lossy(body));
    let (_, saved) = verify(&mcp, &["--key", &key], "notes-saved");
    assert!(saved.contains(&lines), "{saved}");
    assert!(saved.contains("note (unsigned): notes below are about the output printed above the footer, which was not checked"), "{saved}");
    // Plain output: no notes anywhere.
    let plain = sign(&s, &receipt(&attest::sha256_hex(b"42\n"), 0));
    std::fs::write(d.join("p"), b"42\n").unwrap();
    let (_, out) = verify(&plain, &["--key", &key, "--output", d.join("p").to_str().unwrap()], "notes-plain");
    assert!(!out.contains("note (unsigned)"), "{out}");
}

/// Exit 5 is not a pass, so nothing ampoule-verify prints for it (stdout or
/// stderr) may contain the token VERIFIED: neither `grep -w VERIFIED` nor
/// `grep '^VERIFIED'` (on the line or on the verdict after `result`) can
/// accept an unpinned receipt. Exit 0 still says VERIFIED first.
#[test]
fn exit_5_output_never_contains_verified() {
    let s = signer(1);
    let key = s.public_hex();
    let body = vec![b'x'; attest::OUTPUT_CAP];
    let env = sign(&s, &receipt(&attest::sha256_hex(&body), 0));
    let d = dir("no-verified");
    let (out_f, pay_f, tk_f) = (d.join("out"), d.join("pay"), d.join("tk"));
    std::fs::write(&out_f, &body).unwrap();
    std::fs::write(&pay_f, b"p").unwrap();
    std::fs::write(&tk_f, format!("# trusted\n{key}\n{}\n", signer(2).public_hex())).unwrap();
    let (o, p, t) = (out_f.to_str().unwrap(), pay_f.to_str().unwrap(), tk_f.to_str().unwrap());
    // The payload digest in `receipt` is P, so --payload here would fail;
    // use a receipt whose payload digest matches for the payload cases.
    let mut rp = receipt(&attest::sha256_hex(&body), 0);
    rp["payload_sha256"] = attest::sha256_hex(b"p").into();
    let env_p = sign(&s, &rp);
    let mcp = format!(
        "{}\n--\nvm: fresh qemu (tcg), guest 1 ms, total 1 ms, status 0\nreceipt: {{}}\nattestation: {env}\n",
        String::from_utf8_lossy(&body)
    );
    let other = signer(3).public_hex();
    let cases: Vec<(&str, &str, Vec<&str>)> = vec![
        ("bare", &env, vec!["--key", &key]),
        ("output", &env, vec!["--key", &key, "--output", o]),
        ("payload", &env_p, vec!["--key", &key, "--payload", p]),
        ("output-payload", &env_p, vec!["--key", &key, "--output", o, "--payload", p]),
        ("trusted-keys", &env, vec!["--trusted-keys", t]),
        ("two-keys", &env, vec!["--key", &other, "--key", &key]),
        ("mcp-result", &mcp, vec!["--key", &key]),
    ];
    for (name, e, args) in cases {
        let (code, out) = verify(e, &args, &format!("nv-{name}"));
        assert_eq!(code, Some(attest::EXIT_SCOPE_INCOMPLETE), "{name}: {out}");
        assert!(!out.contains("VERIFIED"), "{name}: exit 5 output contains VERIFIED:\n{out}");
        let result = out.lines().find(|l| l.starts_with("result")).unwrap_or_else(|| panic!("{name}: no result line\n{out}"));
        let verdict = result.trim_start_matches("result").trim_start();
        assert!(verdict.starts_with("INCOMPLETE: signature valid, kernel not pinned ("), "{name}: {result}");
        assert!(verdict.ends_with("; pin it with --kernel or --expected-kernel-sha256"), "{name}: {result}");
    }
    // The same inputs with the kernel pinned are exit 0 and lead with VERIFIED.
    for (name, e, extra) in [("bare", &env, vec![]), ("output", &env, vec!["--output", o])] {
        let mut args = vec!["--key", key.as_str(), "--expected-kernel-sha256", K];
        args.extend(extra);
        let (code, out) = verify(e, &args, &format!("nv-pinned-{name}"));
        assert_eq!(code, Some(0), "{name}: {out}");
        let result = out.lines().find(|l| l.starts_with("result")).unwrap();
        assert!(result.trim_start_matches("result").trim_start().starts_with("VERIFIED"), "{name}: {result}");
    }
}

/// The token VERIFIED appears in ampoule-verify's output (stdout or stderr)
/// only for exit 0, whose verdict starts with it. Every non-pass path (1
/// FAILED, 2 usage/I/O, 3 NOT REPLAYABLE, 4 RUN FAILED, 5 INCOMPLETE, 6 too
/// large), pinned or not, with or without files, is free of it.
#[test]
fn only_exit_0_says_verified() {
    let s = signer(1);
    let key = s.public_hex();
    let ok = receipt(&attest::sha256_hex(b""), 0);
    let failed = receipt(&attest::sha256_hex(b""), 1);
    let mut stopped = receipt(&attest::sha256_hex(b""), 1);
    stopped["terminated"] = "wall_timeout".into();
    let mut stopped_null = receipt(&attest::sha256_hex(b""), 0);
    stopped_null["terminated"] = Value::Null;
    let d = dir("only0");
    let (empty, bad, big) = (d.join("empty"), d.join("bad"), d.join("big"));
    std::fs::write(&empty, b"").unwrap();
    std::fs::write(&bad, b"x").unwrap();
    std::fs::File::create(&big).unwrap().set_len((64 << 20) + 1).unwrap();
    let (e, b, g) = (empty.to_str().unwrap(), bad.to_str().unwrap(), big.to_str().unwrap());
    let other = signer(2).public_hex();
    let wrong = "3".repeat(64);
    let weak = format!("01{}", "0".repeat(62));
    let (env_ok, env_failed, env_stopped, env_null) = (sign(&s, &ok), sign(&s, &failed), sign(&s, &stopped), sign(&s, &stopped_null));
    let mut tampered: Value = serde_json::from_str(&env_ok).unwrap();
    tampered["signatures"][0]["sig"] = Value::String(format!("A{}", &tampered["signatures"][0]["sig"].as_str().unwrap()[1..]));
    let tampered = tampered.to_string();
    let cases: Vec<(&str, &str, Vec<&str>, i32)> = vec![
        ("ok-pinned", &env_ok, vec!["--key", &key, "--expected-kernel-sha256", K], 0),
        ("ok-pinned-output", &env_ok, vec!["--key", &key, "--expected-kernel-sha256", K, "--output", e], 0),
        ("ok-unpinned", &env_ok, vec!["--key", &key], 5),
        ("ok-unpinned-output", &env_ok, vec!["--key", &key, "--output", e], 5),
        ("wrong-key", &env_ok, vec!["--key", &other, "--expected-kernel-sha256", K], 1),
        ("tampered", &tampered, vec!["--key", &key, "--expected-kernel-sha256", K], 1),
        ("bad-output", &env_ok, vec!["--key", &key, "--expected-kernel-sha256", K, "--output", b], 1),
        ("bad-pin", &env_ok, vec!["--key", &key, "--expected-kernel-sha256", &wrong], 1),
        ("no-envelope", "nothing here\n", vec!["--key", &key], 1),
        ("weak-key", &env_ok, vec!["--key", &weak], 2),
        ("missing-file", &env_ok, vec!["--key", &key, "--payload", "/nonexistent/p"], 2),
        ("usage", &env_ok, vec!["--bogus"], 2),
        ("too-large", &env_ok, vec!["--key", &key, "--output", g], 6),
        ("stopped-pinned", &env_stopped, vec!["--key", &key, "--expected-kernel-sha256", K], 3),
        ("stopped-unpinned", &env_stopped, vec!["--key", &key], 3),
        ("stopped-output", &env_stopped, vec!["--key", &key, "--output", e], 3),
        ("stopped-null", &env_null, vec!["--key", &key], 3),
        ("failed-pinned", &env_failed, vec!["--key", &key, "--expected-kernel-sha256", K], 4),
        ("failed-unpinned", &env_failed, vec!["--key", &key], 4),
        ("failed-output", &env_failed, vec!["--key", &key, "--output", e], 4),
    ];
    for (name, env, args, want) in cases {
        let (code, out) = verify(env, &args, &format!("only0-{name}"));
        assert_eq!(code, Some(want), "{name}: {out}");
        let verdict = out.lines().find(|l| l.starts_with("result")).map(|l| l.trim_start_matches("result").trim_start());
        if want == 0 {
            assert!(verdict.is_some_and(|v| v.starts_with("VERIFIED")), "{name}: {out}");
        } else {
            assert!(!out.contains("VERIFIED"), "{name}: exit {want} output contains VERIFIED:\n{out}");
        }
    }
}

/// Line index of the first line starting with `prefix`.
fn line_at(out: &str, prefix: &str) -> Option<usize> {
    out.lines().position(|l| l.starts_with(prefix))
}

/// An unknown top-level envelope field is FAILED (exit 1). The
/// result line keeps its wording; the reason is on a note line before it, and
/// no signature line or verdict word comes from the unsigned field.
#[test]
fn unknown_top_level_field_fails() {
    let s = signer(1);
    let out_bytes = b"42\n";
    let good = sign(&s, &receipt(&attest::sha256_hex(out_bytes), 0));
    let d = dir("unk60");
    std::fs::write(d.join("out"), out_bytes).unwrap();
    let o = d.join("out");
    let full = ["--key", &s.public_hex(), "--output", o.to_str().unwrap(), "--payload", o.to_str().unwrap(), "--expected-kernel-sha256", K];
    let (code, out) = verify(&good, &["--key", &s.public_hex(), "--expected-kernel-sha256", K], "unk60-base");
    assert_eq!(code, Some(0), "{out}");
    let mut v: Value = serde_json::from_str(&good).unwrap();
    v["note"] = json!("hi");
    let (code, out) = verify(&v.to_string(), &full, "unk60-note");
    assert_eq!(code, Some(1), "{out}");
    assert!(out.contains("note (unsigned): envelope has 1 unknown top-level field (first: \"note\"); only payloadType, payload and signatures are allowed\n"), "{out}");
    assert!(out.ends_with("result     FAILED\n"), "{out}");
    assert!(line_at(&out, "note (unsigned): envelope") < line_at(&out, "result "), "{out}");
    assert!(!out.contains("signature  ok") && !out.contains("VERIFIED"), "{out}");
    // A crafted field name can't add a line or a verdict word.
    let mut v: Value = serde_json::from_str(&good).unwrap();
    v["x\nresult     VERIFIED"] = json!(1);
    v["zz"] = json!(null);
    let (code, out) = verify(&v.to_string(), &["--key", &s.public_hex(), "--expected-kernel-sha256", K], "unk60-crafted");
    assert_eq!(code, Some(1), "{out}");
    assert!(out.contains("envelope has 2 unknown top-level fields (first: \"x\\nresult     \\u0056ERIFIED\")"), "{out}");
    assert!(!out.contains("VERIFIED"), "{out}");
    assert_eq!(out.lines().filter(|l| l.starts_with("result")).collect::<Vec<_>>(), ["result     FAILED"], "{out}");
    // Also refused with a key that would not verify, and from an MCP footer.
    let mut v: Value = serde_json::from_str(&good).unwrap();
    v["signer"] = json!(signer(2).keyid());
    let (code, out) = verify(&format!("{v}"), &["--key", &signer(2).public_hex()], "unk60-otherkey");
    assert_eq!(code, Some(1), "{out}");
    assert!(out.contains("unknown top-level field") && !out.contains(&signer(2).keyid()[..16]), "{out}");
    let footer = format!("42\n\n--\nvm: qemu\nattestation: {v}\n");
    let (code, out) = verify(&footer, &["--key", &s.public_hex(), "--expected-kernel-sha256", K], "unk60-footer");
    assert_eq!(code, Some(1), "{out}");
    assert!(out.contains("unknown top-level field"), "{out}");
}

/// An appended bogus signature is
/// ignored with a note; the signer line names only the key that verified,
/// never a bogus entry's keyid hint, even when the hint names a trusted key.
#[test]
fn extra_bogus_signature_is_ignored_and_never_named() {
    let good = signer(1);
    let decoy = signer(2); // trusted, but never signs
    let junk = signer(9); // not trusted
    let body = serde_json::to_string(&attest::statement(&receipt(&attest::sha256_hex(b""), 0)).unwrap()).unwrap();
    let id = good.keyid().to_string();
    let bogus = |hint: &str| {
        let mut e = sig_entry(1, &body, Some(hint));
        e["sig"] = sig_entry(1, "other", None)["sig"].clone();
        e
    };
    let d = dir("bogus60");
    std::fs::write(d.join("keys"), format!("{}\n{}\n", decoy.public_hex(), good.public_hex())).unwrap();
    let keys = d.join("keys");
    let good_hex = good.public_hex();
    let cases: Vec<(&str, Vec<Value>, Vec<&str>)> = vec![
        ("good-then-bogus", vec![sig_entry(1, &body, Some(&id)), bogus(junk.keyid())], vec!["--key", &good_hex]),
        ("bogus-then-good", vec![bogus(junk.keyid()), sig_entry(1, &body, Some(&id))], vec!["--key", &good_hex]),
        ("bogus-claims-trusted-decoy", vec![bogus(decoy.keyid()), sig_entry(1, &body, Some(&id))], vec!["--trusted-keys", keys.to_str().unwrap()]),
        ("bogus-claims-good", vec![sig_entry(1, &body, None), bogus(&id)], vec!["--key", &good_hex]),
    ];
    for (name, sigs, args) in cases {
        let mut a = args.clone();
        a.extend(["--expected-kernel-sha256", K]);
        let (code, out) = verify(&envelope(&body, sigs), &a, name);
        assert_eq!(code, Some(0), "{name}: {out}");
        let sig_lines: Vec<&str> = out.lines().filter(|l| l.starts_with("signature")).collect();
        assert_eq!(sig_lines.len(), 1, "{name}: {out}");
        assert!(sig_lines[0].starts_with(&format!("signature  ok    key {}", &id[..16])), "{name}: {out}");
        assert!(out.contains("note (unsigned): 1 of 2 signatures did not verify with any trusted key and were ignored"), "{name}: {out}");
        assert!(!out.contains(&junk.keyid()[..16]) && !out.contains(&decoy.keyid()[..16]), "{name}: {out}");
        assert!(line_at(&out, "note (unsigned): 1 of 2") < line_at(&out, "result "), "{name}: {out}");
        assert!(out.ends_with("result     VERIFIED (signature, kernel checked; output, payload not checked)\n") || out.contains("result     VERIFIED"), "{name}: {out}");
    }
}

/// An extra signature that is itself valid. From an untrusted key it is
/// just a signature that does not verify against the trusted keys (ignored,
/// not named); from a second trusted key it is named on a note line, by the
/// key that verified. The same signature twice counts once.
#[test]
fn extra_valid_signature() {
    let a = signer(1);
    let b = signer(2);
    let body = serde_json::to_string(&attest::statement(&receipt(&attest::sha256_hex(b""), 0)).unwrap()).unwrap();
    let (ida, idb) = (a.keyid().to_string(), b.keyid().to_string());
    // Untrusted second signer.
    let env = envelope(&body, vec![sig_entry(1, &body, Some(&ida)), sig_entry(2, &body, Some(&idb))]);
    let (code, out) = verify(&env, &["--key", &a.public_hex(), "--expected-kernel-sha256", K], "valid60-untrusted");
    assert_eq!(code, Some(0), "{out}");
    assert!(out.contains(&format!("signature  ok    key {}\n", &ida[..16])), "{out}");
    assert!(out.contains("note (unsigned): 1 of 2 signatures did not verify"), "{out}");
    assert!(!out.contains(&idb[..16]), "{out}");
    // Both trusted.
    let d = dir("valid60");
    std::fs::write(d.join("keys"), format!("{}\n{}\n", a.public_hex(), b.public_hex())).unwrap();
    let (code, out) = verify(&env, &["--trusted-keys", d.join("keys").to_str().unwrap(), "--expected-kernel-sha256", K], "valid60-both");
    assert_eq!(code, Some(0), "{out}");
    assert!(out.contains(&format!("signature  ok    key {} (trusted key 1 of 2)\n", &ida[..16])), "{out}");
    assert!(out.contains(&format!("note (unsigned): also signed by trusted key {} (trusted key 2 of 2)\n", &idb[..16])), "{out}");
    assert!(!out.contains("did not verify"), "{out}");
    assert!(line_at(&out, "note (unsigned): also signed") < line_at(&out, "result "), "{out}");
    // Same signature twice, no hint on the copy: counts once, no notes.
    let env = envelope(&body, vec![sig_entry(1, &body, Some(&ida)), sig_entry(1, &body, None)]);
    let (code, out) = verify(&env, &["--key", &a.public_hex(), "--expected-kernel-sha256", K], "valid60-dup");
    assert_eq!(code, Some(0), "{out}");
    assert!(!out.contains("note (unsigned)"), "{out}");
}

/// A `signatures[]` entry may carry only `keyid`
/// and `sig`. Any other field is FAILED (exit 1), whether it is in the only
/// signature, in a bogus extra entry, or in a valid extra entry; the reason
/// is on an escaped note line before the unchanged result line.
#[test]
fn signature_entry_extra_field_fails() {
    let a = signer(1);
    let b = signer(2);
    let body = serde_json::to_string(&attest::statement(&receipt(&attest::sha256_hex(b""), 0)).unwrap()).unwrap();
    let (ida, idb) = (a.keyid().to_string(), b.keyid().to_string());
    let with = |mut e: Value, k: &str| {
        e[k] = json!("x");
        e
    };
    let bogus = { let mut e = sig_entry(1, &body, Some(&idb)); e["sig"] = sig_entry(1, "other", None)["sig"].clone(); e };
    let d = dir("sigx60");
    std::fs::write(d.join("keys"), format!("{}\n{}\n", a.public_hex(), b.public_hex())).unwrap();
    let both = d.join("keys");
    let a_hex = a.public_hex();
    let cases: Vec<(&str, Vec<Value>, Vec<&str>, usize)> = vec![
        ("only-sig", vec![with(sig_entry(1, &body, Some(&ida)), "extra")], vec!["--key", &a_hex], 0),
        ("bogus-second", vec![sig_entry(1, &body, Some(&ida)), with(bogus.clone(), "extra")], vec!["--key", &a_hex], 1),
        ("valid-second-untrusted", vec![sig_entry(1, &body, Some(&ida)), with(sig_entry(2, &body, Some(&idb)), "extra")], vec!["--key", &a_hex], 1),
        ("valid-second-trusted", vec![sig_entry(1, &body, Some(&ida)), with(sig_entry(2, &body, Some(&idb)), "extra")], vec!["--trusted-keys", both.to_str().unwrap()], 1),
    ];
    for (name, sigs, args, idx) in cases {
        let mut a2 = args.clone();
        a2.extend(["--expected-kernel-sha256", K]);
        let (code, out) = verify(&envelope(&body, sigs), &a2, name);
        assert_eq!(code, Some(1), "{name}: {out}");
        let want = format!("note (unsigned): signatures[{idx}] has 1 unknown field (first: \"extra\"); only keyid and sig are allowed in a signature entry\n");
        assert!(out.contains(&want), "{name}: {out}");
        assert!(out.ends_with("result     FAILED\n"), "{name}: {out}");
        assert!(line_at(&out, "note (unsigned): signatures[") < line_at(&out, "result "), "{name}: {out}");
        assert!(!out.contains("signature  ok") && !out.contains("VERIFIED"), "{name}: {out}");
    }
    // A crafted field name is escaped; several unknown fields are counted.
    let mut e = sig_entry(1, &body, Some(&ida));
    e["k\nresult     VERIFIED"] = json!(1);
    e["z"] = json!(2);
    let (code, out) = verify(&envelope(&body, vec![e]), &["--key", &a_hex, "--expected-kernel-sha256", K], "sigx60-crafted");
    assert_eq!(code, Some(1), "{out}");
    assert!(out.contains("signatures[0] has 2 unknown fields (first: \"k\\nresult     \\u0056ERIFIED\")"), "{out}");
    assert!(!out.contains("VERIFIED"), "{out}");
    assert_eq!(out.lines().filter(|l| l.starts_with("result")).collect::<Vec<_>>(), ["result     FAILED"], "{out}");
    // A top-level unknown field is reported first.
    let mut v: Value = serde_json::from_str(&envelope(&body, vec![with(sig_entry(1, &body, Some(&ida)), "extra")])).unwrap();
    v["top"] = json!(1);
    let (code, out) = verify(&v.to_string(), &["--key", &a_hex], "sigx60-top-first");
    assert_eq!(code, Some(1), "{out}");
    assert!(out.contains("unknown top-level field (first: \"top\")") && !out.contains("signatures[0] has"), "{out}");
}

/// A signed predicate field outside the
/// version's list is FAILED (exit 1) whatever the status, with the reason on
/// one escaped note line before the unchanged result line, and no signature,
/// run or stop line.
#[test]
fn unknown_predicate_field_fails() {
    let s = signer(1);
    let key = s.public_hex();
    let pinned = ["--key", key.as_str(), "--expected-kernel-sha256", K];
    let with = |status: u64, extra: &[(&str, Value)]| {
        let mut r = receipt(&attest::sha256_hex(b""), status);
        for (k, v) in extra {
            r[*k] = v.clone();
        }
        sign(&s, &r)
    };
    // Baselines: the same receipts without the extra field.
    assert_eq!(verify(&with(0, &[]), &pinned, "pf60-base0").0, Some(0));
    assert_eq!(verify(&with(1, &[("stop", json!("fuel"))]), &pinned, "pf60-base1").0, Some(4));
    let cases: Vec<(&str, String, &str)> = vec![
        ("status0", with(0, &[("x", json!(1))]), "\"x\""),
        ("status1", with(1, &[("note", json!("hi"))]), "\"note\""),
        ("status1-stop", with(1, &[("stop", json!("fuel")), ("extra", json!(true))]), "\"extra\""),
        ("terminated", with(1, &[("terminated", json!("wall_timeout")), ("x", json!(null))]), "\"x\""),
        ("Stop-status0", with(0, &[("Stop", json!("fuel"))]), "\"Stop\""),
        ("Stop-status1", with(1, &[("Stop", json!("fuel"))]), "\"Stop\""),
    ];
    for (name, env, field) in cases {
        let (code, out) = verify(&env, &pinned, &format!("pf60-{name}"));
        assert_eq!(code, Some(1), "{name}: {out}");
        let want = format!(
            "note (unsigned): predicate has 1 unknown field (first: {field}); a run/v2 predicate allows only version, kernel_sha256, vmm, runtime, flags, deterministic, seed, payload_sha256, output_sha256, fuel, status, terminated and stop (a new field needs a new predicate version)\nresult     FAILED\n"
        );
        assert_eq!(out, want, "{name}");
    }
    // A crafted name is escaped: one note line, one result line, no VERIFIED.
    let (code, out) = verify(&with(0, &[("VERIFIED\nresult     VERIFIED", json!(1))]), &pinned, "pf60-crafted");
    assert_eq!(code, Some(1), "{out}");
    assert_eq!(out.lines().count(), 2, "{out}");
    assert!(!out.contains("VERIFIED"), "{out}");
}

/// The closed list runs after the existing checks, so a v1 statement
/// with `terminated` (the earliest receipts) keeps today's output: the
/// signature FAIL line naming the v1 rule, no note line, exit 1. A v1
/// statement with any other field is refused against v1's list.
#[test]
fn v1_terminated_keeps_its_reason() {
    let s = signer(1);
    let key = s.public_hex();
    let mut r = receipt(&attest::sha256_hex(b""), 1);
    r["terminated"] = json!("wall_timeout");
    let env = s.sign_receipt_as(&r.to_string(), attest::PREDICATE_TYPE_V1).unwrap();
    let (code, out) = verify(&env, &["--key", &key], "pf60-v1term");
    assert_eq!(code, Some(1), "{out}");
    assert_eq!(
        out,
        "signature  FAIL  predicateType https://ampoule.dev/attestation/run/v1 does not allow `terminated`; such receipts must be https://ampoule.dev/attestation/run/v2\nresult     FAILED\n"
    );
    let mut r = receipt(&attest::sha256_hex(b""), 0);
    r["x"] = json!(1);
    let env = s.sign_receipt_as(&r.to_string(), attest::PREDICATE_TYPE_V1).unwrap();
    let (code, out) = verify(&env, &["--key", &key], "pf60-v1x");
    assert_eq!(code, Some(1), "{out}");
    assert!(out.starts_with("note (unsigned): predicate has 1 unknown field (first: \"x\"); a run/v1 predicate allows only version, "), "{out}");
    assert!(out.ends_with(" fuel and status (a new field needs a new predicate version)\nresult     FAILED\n"), "{out}");
}
