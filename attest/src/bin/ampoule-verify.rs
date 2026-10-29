//! Check a signed Ampoule receipt without trusting the host that produced it.
//!
//!   ampoule-verify ENVELOPE (--key PUBKEY | --trusted-keys FILE)...
//!                  [--payload FILE] [--output FILE] [--kernel FILE] [--expected-kernel-sha256 HEX]
//!                  (--payload FILE is required for exit 0)
//!   ampoule-verify pubkey [KEYFILE]     print the public key of a signing key
//!   ampoule-verify keygen [KEYFILE]     create a signing key (default ~/.ampoule/signing.key)
//!   ampoule-verify --help | --version  usage and exit codes / version, exit 0
//!
//! ENVELOPE is a DSSE JSON file, `-` for stdin, or saved MCP output with its
//! footer (`--` then `vm: ...`), or a file holding only the `attestation:`
//! line. Only the `attestation:` line inside the footer counts: one in the
//! program output above it, or in other text without a footer, is ignored. PUBKEY is 64 hex characters or a file with them;
//! it is the trust anchor and must come from somewhere other than the envelope.
//! `--key` may be repeated, and `--trusted-keys FILE` adds every key in FILE
//! (one 64-hex key per line; blank lines and `#` comments ignored): the
//! receipt is accepted when a signature from any one of them verifies.
//! Weak public keys (small-order points such as the identity, under which
//! anyone can forge a signature) are refused as a usage error (exit 2), and
//! signatures are checked with strict Ed25519 (`verify_strict`).
//! The optional files are re-hashed and compared with the signed digests:
//! --output the exact output bytes, --payload the exact bytes sent to the VM
//! (the source for run_js / run_python / run_code), --kernel the kernel ELF.
//! `--expected-kernel-sha256 HEX` pins the kernel by digest without the file.
//! To re-execute a deterministic run, use `verify --replay ENVELOPE`.
//!
//! Exit codes:
//!   0 VERIFIED: signature and every given digest match, status 0, and the
//!     kernel is pinned (--kernel or --expected-kernel-sha256). The result
//!     line names any optional file not given, e.g.
//!     `VERIFIED (payload, kernel checked; output not checked)`. --payload is
//!     required for a pass: without it that case is exit 2 (see below).
//!   1 FAILED: signature, statement, predicate or a digest.
//!   2 usage or I/O: bad arguments, an unreadable ENVELOPE, key or
//!     --output/--payload/--kernel/--trusted-keys file; also a receipt
//!     checked without --payload that would otherwise be exit 0 (every
//!     other verdict, 1, 3, 4 and 5, keeps its code without --payload).
//!   3 NOT REPLAYABLE: the signed receipt says the host stopped the run
//!     (`"terminated": "wall_timeout"`; any `terminated` key, even null,
//!     counts): `NOT REPLAYABLE: signature valid, terminated=wall_timeout
//!     (<scope>)`. The reason is printed only if it is a plain `[a-z_]`
//!     token of at most 64 characters (`null` for a JSON null), else as
//!     `terminated=non-standard`, so a signed reason cannot forge a line.
//!   4 RUN FAILED: the signed receipt is genuine but its `status` is
//!     nonzero, so it attests a failed run: `RUN FAILED: signature valid,
//!     status 1, program error (<scope>)`. (3 outranks 4.) A run that used
//!     up its fuel budget is signed with `"stop": "fuel"`: same result
//!     line and exit 4, plus a `stop       fuel: ...` detail line above it.
//!   5 INCOMPLETE: the signature is valid, status 0, nothing failed, but the
//!     kernel was not pinned. Not a pass, so the line never contains the word
//!     VERIFIED (a `grep -w VERIFIED` must not accept it). It ends with the
//!     same scope suffix as NOT REPLAYABLE and RUN FAILED, then how to pin:
//!     `INCOMPLETE: signature valid, kernel not pinned (payload checked;
//!     output, kernel not checked); pin it with --kernel or
//!     --expected-kernel-sha256`. Both lists in a scope are in the order
//!     output, payload, kernel.
//!   6 INPUT TOO LARGE: ENVELOPE (or stdin), --output, --payload or
//!     --trusted-keys is over 64 MiB (real receipts are 1-2 KiB); nothing is
//!     checked: `INPUT TOO LARGE: over the 64 MiB input limit; nothing
//!     checked` (its own word, not FAILED, which is exit 1). The --kernel ELF is hashed as a stream and is not capped.
//! Precedence when several apply (most serious wins), from attest::exit_code:
//!   2 (and 6, both before any verdict) > 1 > 3 > 4 > 5 > 0
//! e.g. an unpinned check of a failed run is 4, an unpinned not-replayable
//! run is 3. JSON with duplicate keys is FAILED.
//! Only exit 0 prints the word VERIFIED; no other result line contains it,
//! so `grep -w VERIFIED` cannot accept a non-pass.

use std::path::PathBuf;
use std::process::exit;

const USAGE: &str = "\
usage: ampoule-verify ENVELOPE (--key PUBKEY | --trusted-keys FILE)... [--payload FILE] [--output FILE]
                      [--kernel FILE] [--expected-kernel-sha256 HEX]
       (--payload FILE is required for exit 0; without it a would-be pass is exit 2)
       ampoule-verify pubkey [KEYFILE]
       ampoule-verify keygen [KEYFILE]
       ampoule-verify --help | --version
";

/// Exit-code table, for --help only: a usage error (exit 2) prints just the
/// synopsis, so no non-pass output contains the word VERIFIED.
const EXIT_HELP: &str = "\
exit codes: 0 VERIFIED (kernel pinned), 1 FAILED, 2 usage or I/O (also a weak key, an unreadable file, no --payload on an otherwise passing check),
            3 NOT REPLAYABLE (signature valid, host stopped the run), 4 RUN FAILED (signature valid, nonzero status),
            5 INCOMPLETE (signature valid, kernel not pinned; not a pass), 6 input over 64 MiB
precedence: 2 (and 6) > 1 > 3 > 4 > 5 > 0: the most serious problem wins; a missing --payload turns only a would-be 0 into 2
";

/// A usage error: the usage text on stderr, exit 2.
fn usage() -> ! {
    eprint!("{USAGE}(ampoule-verify --help lists the exit codes)\n");
    exit(2)
}

fn die(msg: impl std::fmt::Display) -> ! {
    eprintln!("{msg}");
    exit(2)
}

/// Read an input file (or stdin for `-`) under the 64 MiB cap: too large is
/// exit 6, any other read error is a usage/I-O error (exit 2).
fn read_input(label: &str, path: &str) -> Vec<u8> {
    let r = if path == "-" { attest::read_capped(std::io::stdin().lock()) } else { attest::read_file_capped(path) };
    match r {
        Ok(b) => b,
        Err(attest::ReadError::TooLarge) => {
            eprintln!("{label}{path}: {}", attest::ReadError::TooLarge);
            println!("result     INPUT TOO LARGE: over the {} MiB input limit; nothing checked", attest::MAX_INPUT_BYTES >> 20);
            exit(attest::EXIT_INPUT_TOO_LARGE)
        }
        Err(e) => die(format!("{label}{path}: {e}")),
    }
}

fn key_path(arg: Option<String>) -> PathBuf {
    arg.map(PathBuf::from).or_else(attest::default_key_path).unwrap_or_else(|| die("no key path: pass KEYFILE or set AMPOULE_SIGNING_KEY"))
}

/// Keys from a trusted-keys file: one 64-hex key per line, `#` comments.
fn trusted_keys_file(path: &str) -> Vec<ed25519_dalek::VerifyingKey> {
    let text = String::from_utf8(read_input("--trusted-keys ", path)).unwrap_or_else(|_| die(format!("--trusted-keys {path}: not UTF-8 text")));
    let mut keys = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.len() != 64 || !line.bytes().all(|b| b.is_ascii_hexdigit()) {
            die(format!("--trusted-keys {path}:{}: not a 64-hex public key", n + 1));
        }
        keys.push(attest::parse_public_key(line).unwrap_or_else(|e| die(format!("--trusted-keys {path}:{}: {e}", n + 1))));
    }
    if keys.is_empty() {
        die(format!("--trusted-keys {path}: no keys in file"));
    }
    keys
}

fn main() {
    let mut args = std::env::args().skip(1);
    let first = args.next().unwrap_or_else(|| usage());
    match first.as_str() {
        "pubkey" | "keygen" => {
            // `keygen --help` used to write a private key to a file
            // named `--help`. No option is taken here: -h/--help prints the
            // usage (exit 0); any other argument starting with `-`, or more
            // than one argument, is a usage error (exit 2) and touches no file.
            let rest: Vec<String> = args.by_ref().collect();
            if rest.iter().any(|a| a == "-h" || a == "--help") {
                print!("{USAGE}{EXIT_HELP}");
                return;
            }
            if let Some(a) = rest.iter().find(|a| a.starts_with('-')) {
                eprintln!("ampoule-verify {first}: unknown option {a:?} (KEYFILE may not start with '-'; use ./{a} for such a file)");
                usage();
            }
            if rest.len() > 1 {
                eprintln!("ampoule-verify {first}: takes at most one KEYFILE");
                usage();
            }
            let path = key_path(rest.into_iter().next());
            if first == "pubkey" && !path.exists() {
                eprintln!("{} does not exist; run `ampoule-verify keygen` first", path.display());
                exit(1);
            }
            match attest::Signer::load_or_create(&path) {
                Ok((s, created)) => {
                    if created {
                        eprintln!("created {}", path.display());
                    }
                    println!("{}", s.public_hex());
                }
                Err(e) => {
                    eprintln!("{e}");
                    exit(1);
                }
            }
            return;
        }
        "-h" | "--help" => {
            print!("{USAGE}{EXIT_HELP}");
            return;
        }
        "-V" | "--version" => {
            println!("ampoule-verify {} (predicate {})", env!("CARGO_PKG_VERSION"), attest::PREDICATE_TYPE);
            return;
        }
        _ => {}
    }

    let mut keys = Vec::new();
    let (mut output, mut payload, mut kernel, mut expected_kernel) = (None, None, None, None);
    while let Some(a) = args.next() {
        let mut val = || args.next().unwrap_or_else(|| usage());
        let once = |slot: &mut Option<String>, v: String| {
            if slot.replace(v).is_some() {
                die(format!("{a} given twice"));
            }
        };
        match a.as_str() {
            "--key" => {
                let k = val();
                keys.push(attest::parse_public_key(&k).unwrap_or_else(|e| die(e)));
            }
            "--trusted-keys" => keys.extend(trusted_keys_file(&val())),
            "--output" => once(&mut output, val()),
            "--payload" => once(&mut payload, val()),
            "--kernel" => once(&mut kernel, val()),
            "--expected-kernel-sha256" => once(&mut expected_kernel, val()),
            _ => usage(),
        }
    }
    if keys.is_empty() {
        die("--key or --trusted-keys is required: the signer's public key is the trust anchor");
    }
    let expected_kernel = expected_kernel.map(|h| {
        let h = h.trim().to_ascii_lowercase();
        if h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
            die("--expected-kernel-sha256 must be 64 hex characters");
        }
        h
    });

    let text = String::from_utf8(read_input(if first == "-" { "stdin " } else { "" }, &first)).unwrap_or_else(|_| die(format!("{first}: not UTF-8 text")));
    // Every file to compare is read before any verdict: a missing or
    // unreadable one is a usage error (exit 2), one over the 64 MiB cap is
    // exit 6, not a failed receipt. The kernel is hashed as a stream.
    let read = |label: &str, f: &Option<String>| f.as_ref().map(|f| attest::sha256_hex(&read_input(&format!("--{label} "), f)));
    let output_bytes = output.as_ref().map(|f| read_input("--output ", f));
    let output = output_bytes.as_ref().map(|b| attest::sha256_hex(b));
    let payload = read("payload", &payload);
    let kernel = kernel.as_ref().map(|f| attest::sha256_file_hex(f).unwrap_or_else(|e| die(format!("--kernel {f}: {e}"))));

    let Some(envelope) = attest::find_envelope(&text) else {
        println!("signature  FAIL  no DSSE envelope found in {first}");
        println!("result     FAILED");
        exit(1)
    };
    // An unknown top-level field, or an unknown field in any signature
    // entry, is FAILED before any signature line;
    // the reason goes on a note line and the result line keeps its wording.
    if let Err(e) = attest::check_envelope_fields(&envelope) {
        println!("{}{e}", attest::NOTE_PREFIX);
        println!("result     FAILED");
        exit(1)
    }
    let check = match attest::verify_envelope_checked(&envelope, &keys) {
        Ok(v) => v,
        // A signed predicate field outside its version's closed list,
        // found after every existing check: the reason on a note line, the
        // result line unchanged, no signature or run line.
        Err(attest::VerifyError::UnknownPredicateFields(e)) => {
            println!("{}{e}", attest::NOTE_PREFIX);
            println!("result     FAILED");
            exit(1)
        }
        Err(e) => {
            println!("signature  FAIL  {e}");
            println!("result     FAILED");
            exit(1)
        }
    };
    let k = check.key;
    let sig_notes = attest::signature_note_lines(&check, &keys);
    let verdict = check.verdict;
    let p = &verdict.statement()["predicate"];
    let which = if keys.len() > 1 { format!(" (trusted key {} of {})", k + 1, keys.len()) } else { String::new() };
    // Names only the key whose signature verified, never a keyid hint.
    println!("signature  ok    key {}{which}", &attest::keyid(&keys[k])[..16]);
    for n in &sig_notes {
        println!("{}{n}", attest::NOTE_PREFIX);
    }
    println!(
        "run        {} on {}, status {}, fuel {}, {}",
        p["runtime"].as_str().unwrap_or("?"),
        p["vmm"].as_str().unwrap_or("?"),
        p["status"],
        p["fuel"],
        if p["deterministic"].as_bool() == Some(true) { format!("deterministic seed {}", p["seed"]) } else { "not deterministic".into() }
    );
    // A signed fuel stop. A detail line, not a verdict: the result line
    // and exit code stay those of the status (RUN FAILED, 4).
    if attest::fuel_stop(p) {
        println!("stop       {}", attest::FUEL_STOP_DETAIL);
    }

    let mut pass = true;
    let (mut checked, mut unchecked) = (Vec::new(), Vec::new());
    for (label, file, field) in [("output", &output, "output_sha256"), ("payload", &payload, "payload_sha256"), ("kernel", &kernel, "kernel_sha256")] {
        let want = p[field].as_str().unwrap_or("");
        match file {
            None if label == "kernel" && expected_kernel.is_some() => {}
            None => {
                println!("{label:<10} {}  (not checked)", want.get(..16).unwrap_or(want));
                unchecked.push(label);
            }
            Some(got) => {
                let ok = got == want;
                pass &= ok;
                checked.push(label);
                println!("{label:<10} {}  {}", &got[..16], if ok { "matches" } else { "DIFFERS" });
            }
        }
    }
    if let Some(h) = &expected_kernel {
        let want = p["kernel_sha256"].as_str().unwrap_or("");
        let ok = h == want;
        pass &= ok;
        if !checked.contains(&"kernel") {
            checked.push("kernel");
        }
        println!("kernel     {}  {} --expected-kernel-sha256{}", want.get(..16).unwrap_or(want), if ok { "matches" } else { "DIFFERS from" }, if ok { String::new() } else { format!(" {}", &h[..16]) });
    }
    // Unsigned notes about the output bytes, the same lines the MCP footer
    // and verify_receipt print: from --output, else from the program output
    // above the footer of a saved MCP result (informational only; that copy
    // is not compared with the signed digest unless given as --output).
    let note_src: Option<&[u8]> = output_bytes.as_deref().or_else(|| attest::output_above_footer(&text));
    if let Some(bytes) = note_src {
        let notes = attest::output_note_lines(bytes);
        if !notes.is_empty() && output_bytes.is_none() {
            println!("{}notes below are about the output printed above the footer, which was not checked (pass --output to check it)", attest::NOTE_PREFIX);
        }
        print!("{notes}");
    }
    if let Some(status) = verdict.run_failed_status() {
        println!("{}the run itself reported status {status}, {}: this receipt attests a failed run", attest::NOTE_PREFIX, attest::status_meaning(status));
        println!("{}status is the kernel's result code, not the program's exit code (sys.exit(2) is status 1)", attest::NOTE_PREFIX);
    }
    let scope = match (checked.is_empty(), unchecked.is_empty()) {
        (_, true) => String::new(),
        (true, false) => format!(" (signature only; {} not checked)", unchecked.join(", ")),
        (false, false) => format!(" ({} checked; {} not checked)", checked.join(", "), unchecked.join(", ")),
    };
    if pass {
        println!("checked    signature{}{}", checked.iter().map(|c| format!(", {c}")).collect::<String>(), if unchecked.is_empty() { String::new() } else { format!("; not checked: {}", unchecked.join(", ")) });
    }
    // The verdict is ranked in one place (attest::exit_code). A run stopped
    // by the host wall-clock safety net is signed as such and is never a
    // pass: the signer could set the field to dodge replay, so tools must
    // fail closed on it (exit 3); it outranks a nonzero status (4), which
    // outranks an unpinned kernel (5).
    let code = attest::exit_code(attest::CheckResult {
        failed: !pass,
        not_replayable: verdict.not_replayable_reason().is_some(),
        run_failed: verdict.run_failed_status().is_some(),
        kernel_pinned: checked.contains(&"kernel"),
    });
    match code {
        1 => println!("result     FAILED"),
        attest::EXIT_NOT_REPLAYABLE => println!("result     NOT REPLAYABLE: signature valid, terminated={}{scope}", attest::reason_for_display(verdict.not_replayable_reason().unwrap_or(""))),
        attest::EXIT_RUN_FAILED => println!("result     RUN FAILED: signature valid, {}{scope}", attest::status_verdict(verdict.run_failed_status().unwrap_or(0))),
        // Not a pass: lead with INCOMPLETE and never print the word VERIFIED,
        // so grepping for VERIFIED cannot accept an unpinned receipt.
        attest::EXIT_SCOPE_INCOMPLETE => {
            println!("result     INCOMPLETE: signature valid, kernel not pinned{scope}; pin it with --kernel or --expected-kernel-sha256")
        }
        // Everything else checked out. Without --payload a valid signature
        // says nothing about what ran, so this is not a pass: a usage error
        // (exit 2), never VERIFIED. Only here, so 1 (bad signature or a
        // digest that differs), 3, 4 and 5 keep their codes.
        _ if payload.is_none() => {
            eprintln!("ampoule-verify: --payload FILE is required (the exact program bytes sent to the VM; module plus input for wasm)");
            // The scope leaves payload out: the head already says so.
            let rest: Vec<&str> = unchecked.iter().copied().filter(|l| *l != "payload").collect();
            let scope = match (checked.is_empty(), rest.is_empty()) {
                (_, true) => String::new(),
                (true, false) => format!(" (signature only; {} not checked)", rest.join(", ")),
                (false, false) => format!(" ({} checked; {} not checked)", checked.join(", "), rest.join(", ")),
            };
            println!("result     USAGE: payload not checked{scope}; pass --payload FILE");
            exit(2)
        }
        _ => println!("result     VERIFIED{scope}"),
    }
    exit(code);
}
