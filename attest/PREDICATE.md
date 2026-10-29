# Ampoule run predicate, v2 (and v1)

Predicate type: `https://ampoule.dev/attestation/run/v2` (current).
Receipts signed before v2 carry `https://ampoule.dev/attestation/run/v1`;
see [v2: differences from v1](#v2-differences-from-v1).

The URI is permanent: every signed receipt carries it. A breaking change to
the fields gets a new version (`/v2`), never an edit to this one. From the closed-list change
on, each version's field list is closed (see [Closed field lists](#closed-field-lists)):
any new field, breaking or not, needs a new predicate version.

An in-toto [Statement v1] with this predicate records one execution of
untrusted code inside a sealed Ampoule micro-VM: which kernel ran it, what
went in, what came out, and how much work it took. It is carried in a
[DSSE] envelope signed with Ed25519.

[Statement v1]: https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md
[DSSE]: https://github.com/secure-systems-lab/dsse/blob/master/protocol.md

## Statement

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{ "name": "output", "digest": { "sha256": "<output_sha256>" } }],
  "predicateType": "https://ampoule.dev/attestation/run/v2",
  "predicate": {
    "version": 1,
    "kernel_sha256": "e028af09…",
    "vmm": "firecracker",
    "runtime": "js",
    "flags": 260,
    "deterministic": true,
    "seed": 7,
    "payload_sha256": "bf75c921…",
    "output_sha256": "12cece5a…",
    "fuel": 14354058,
    "status": 0
  }
}
```

The subject is the output, the artifact the run produced. Its digest must
equal `predicate.output_sha256`; verifiers reject a statement where they differ.

## Predicate fields

| field | meaning |
|---|---|
| `version` | Receipt format version: the JSON integer `1`, fixed for v1 and v2. Any other value or type (`2`, `"1"`, `1.0`) is rejected; a format change gets a new predicate type, not a new `version`. |
| `kernel_sha256` | Required. SHA-256 of the kernel ELF the VM booted. The language runtimes (QuickJS, CPython) are embedded in the kernel, so this pins them too. |
| `vmm` | `qemu` or `firecracker`. Informational: deterministic runs give the same output and fuel on both. |
| `runtime` | `rhai`, `wasm`, `js` or `python`. |
| `flags` | Request flags as sent in the mailbox (runtime bit, `0x100` = deterministic). |
| `deterministic` | Clock and randomness derived from `seed` (the WASI realtime clock reads 2026-01-01T00:00:00Z + `seed` s + 1 ms per read), a runaway ends on a fixed budget that replay reproduces exactly: wasmi fuel for wasm (20G), js (2T) and python (2T, warm and cold path alike), an operation count for rhai. A host wall-clock cutoff (js 20 s, python 30 s, wasm 20 s) remains as a safety net for hosts too slow to reach the budget; a run it stops gets `terminated` and is not replayable. Only these runs can be re-executed to the same result. |
| `seed` | The seed used for clock and randomness. |
| `payload_sha256` | SHA-256 of the exact request bytes: the source for rhai/js/python; for wasm, `u32le module_len ‖ module ‖ input`. Computed by the guest and checked by the host. |
| `output_sha256` | SHA-256 of the exact output bytes, computed by the guest and checked by the host. See [Output bytes](#output-bytes-cap-and-utf-8) for what those bytes are. |
| `fuel` | Work done: wasmi fuel consumed for wasm/js/python, Rhai operations counted by the engine for rhai. Wasmi fuel is a coarse cost measure (charged per block of instructions at weighted costs, plus per byte of bulk memory work), not an instruction count; two different inputs can use the same fuel. For deterministic runs, part of what replay must reproduce. |
| `status` | The kernel's result code for the run, **not the program's exit code**: `0` success, `1` program error (an uncaught exception, any nonzero exit, a trap or a limit), `2` bad request or runtime unavailable, other values are limits or faults. Python's `sys.exit(2)` gives status 1, as does an uncaught exception (CPython exits with 1): the kernel maps every nonzero WASI `proc_exit(N)` to status 1 and appends `!! exit code N` to the output, so the program's own code is in the output, not in `status`. Tools print it as `status 1 (program error)`. A signed receipt with a nonzero status attests a failed run, not a successful one: `ampoule-verify` prints `RUN FAILED: signature valid, status N (meaning)` and exits 4, `verify --replay` prints `REPLAY MATCHED, RUN FAILED: status N` and exits 4 when the rerun matches (it never says `REPLAY OK` for such a receipt), `verify_receipt` answers `RUN FAILED: signature valid, status N (meaning) (…)`, and the library returns `Verdict::VerifiedRunFailed`, never `Verdict::Verified`. `terminated` outranks it (exit 3): a stopped run's status describes the stop. |
| `stop` | Optional; absent on every receipt from an earlier kernel and on every run that did not use up its budget. `"fuel"`: the run used up its fuel budget (wasmi fuel for wasm, js and python; the operation limit for rhai), i.e. a runaway, not a crash (response header word at offset 112 = 2). Such a run is deterministic, so it **stays replayable**: `status` is 1, and the verdict is the status verdict (`ampoule-verify` RUN FAILED, exit 4; `verify --replay` REPLAY MATCHED, RUN FAILED, exit 4, and replay must reproduce the stop: a rerun that does or does not stop on fuel where the receipt says otherwise is `REPLAY FAILED: stop differs`). Tools print it as a detail line (`stop       fuel: ...` in `ampoule-verify`, `stop: fuel: ...` in `verify_receipt`, `stop    fuel  matches receipt` in replay); the result line is the same as for the same receipt without `stop`. It is a separate field, not a `terminated` value, because any `terminated` key means not replayable. Verifiers from before `stop` ignore it (unknown extra field) and report the same RUN FAILED, exit 4. Strict: any value other than `"fuel"`, a status other than 1, or `stop` together with `terminated` is FAILED (exit 1), and the value is never printed as it is. Inside the signed statement, so removing or adding it without re-signing breaks the signature. |
| `terminated` | Optional; absent for a run that ended normally. `"wall_timeout"`: the guest was stopped by the host wall-clock safety net, not by fuel (response header word at offset 112 = 1). Whether that fires depends on host speed, so the run is **not replayable** even when `deterministic` is true. Verifiers must never report such a receipt as a pass: `ampoule-verify` prints `NOT REPLAYABLE: signature valid, terminated=wall_timeout` and `verify --replay` prints `REPLAY N/A`, both exit 3. The presence of the key is what counts: any other value, including `null`, is treated the same way (fail closed). The value is printed only when it is a plain token of 1 to 64 characters from `[a-z_]` (`wall_timeout`; `null` for a JSON null); any other value (the empty string, upper case, spaces, newlines, control characters, objects, numbers) prints as `terminated=non-standard`, so a signed reason can never add a line or the word VERIFIED to a verifier's output. The library's `verify_envelope()` returns `Verdict::VerifiedNotReplayable` for it, never `Verdict::Verified`. The field is inside the signed statement, so removing or adding it without re-signing breaks the signature. |

### Field types (strict parsing)

Verifiers check every field, and reject the receipt (FAILED, exit 1) when one
is missing, `null` or of the wrong type:

| field | type and allowed values |
|---|---|
| `version` | integer `1` |
| `kernel_sha256`, `payload_sha256`, `output_sha256` | string, exactly 64 lowercase hex characters |
| `vmm` | `"qemu"` or `"firecracker"` |
| `runtime` | `"rhai"`, `"wasm"`, `"js"` or `"python"` |
| `deterministic` | boolean, equal to bit `0x100` of `flags` |
| `flags`, `seed`, `fuel`, `status` | integer from 0 to 2^64-1 (no sign, no fraction, no exponent) |
| `stop` | optional, exactly `"fuel"`, only with `status` 1 and without `terminated`; v2 only |
| `terminated` | optional, any value (its presence is what counts); v2 only |
| any other field | none allowed: see [Closed field lists](#closed-field-lists) |

The statement must have exactly one subject.

### Closed field lists

Each predicate version has a closed list of fields. A signed predicate with
any other field is FAILED (exit 1), whatever its `status`, and whether or not
it carries `terminated` or `stop`. Field names are case-sensitive: `Stop` or
`Terminated` is an unknown field, not `stop` or `terminated`.

| predicateType | allowed predicate fields (nothing else) |
|---|---|
| `.../run/v1` | `version`, `kernel_sha256`, `vmm`, `runtime`, `flags`, `deterministic`, `seed`, `payload_sha256`, `output_sha256`, `fuel`, `status` |
| `.../run/v2` | the v1 fields, plus `terminated` and `stop` (both optional) |

The lists are `attest::PREDICATE_FIELDS_V1` and `attest::PREDICATE_FIELDS_V2`.
They will not grow: a new field needs a new predicate version (`/v3`), so a
verifier never silently ignores a field it does not understand. Before the closed lists
unknown predicate fields were ignored (in-toto predicates are open); verifiers
from before the closed lists are not changed and still ignore them.

The check runs after every other predicate check (field types, v1's
`terminated`/`stop` rule, the `stop` rules), so a receipt those already refuse
keeps its reason. A v1 statement carrying `terminated` (receipts from the
earliest receipts) is still reported as `predicateType .../run/v1 does not allow
`terminated`; ...`, exit 1, with no note line. The signature is checked
first: an unknown field in an envelope whose signature does not verify is
reported as a signature failure.

Tools print the reason on one escaped note line before an unchanged result
line, as for unknown envelope fields, with no signature, run or stop line:

    note (unsigned): predicate has 1 unknown field (first: "x"); a run/v2 predicate allows only version, kernel_sha256, vmm, runtime, flags, deterministic, seed, payload_sha256, output_sha256, fuel, status, terminated and stop (a new field needs a new predicate version)
    result     FAILED

The field name goes through the same escaping as other signed text, so a
crafted name can never add a line or the word VERIFIED. `verify --replay`
prints the note before `REPLAY FAILED: receipt does not parse strictly`
(exit 1), before anything runs. With `--key` this holds for every receipt
(a `terminated` receipt with an unknown field is exit 1, not REPLAY N/A).
Without `--key` the list is checked after the not-replayable check, so a
`terminated` receipt is REPLAY N/A (exit 3) as before. A bare receipt (no
statement around it, so no predicate type; only `verify --replay` accepts one)
has no signature, so `--key` with a bare receipt is refused before anything
boots (exit 2, "a bare receipt has no signature to check"). Without `--key` its
content is replayed and the output says exactly `unsigned receipt: signature
not checked` in place of a signature line (a matching run is still REPLAY OK,
exit 0, never VERIFIED). It is checked against the widest list, run/v2's: a
field outside it is the same note line and REPLAY FAILED (exit 1), and a
`terminated` one is REPLAY N/A (exit 3).
`ampoule-verify` and MCP never accept a bare receipt (FAILED, no DSSE envelope
found).
The MCP `verify_receipt` tool answers `result: FAILED (predicate has an
unknown field)`, with the same note line under it.

### Output bytes: cap and UTF-8

`output_sha256` covers exactly the bytes the guest captured, and those can
differ from what the program wrote in two ways. Kernels up to and including
the current v2 kernels (`60ba9149…`) do this without any marker in the output:

- **64 KiB cap.** Output is cut at 65,536 bytes (backing off up to 3 bytes to
  a UTF-8 boundary). A stop line the kernel appends after the program's own
  output (`!! fuel limit`, `!! <error>`, …) is cut with it, so a
  program that fills the cap can end its output with a fake stop line. Only
  the signed `status` (and `terminated`, and later `stop`) say how the run ended; never parse
  the text for it.
- **Lossy UTF-8.** For Wasm, JavaScript and Python, bytes the program writes
  that are not valid UTF-8 are replaced with U+FFFD before hashing. Rhai
  output is always valid UTF-8.

Receipts stay valid and replayable (the guest does the same thing on every
run), so the hardening release flags these cases instead of changing what is
signed: a note is printed when the output is exactly at the cap (a cut of
ASCII text always lands there), or 1 to 3 bytes short of it and contains
multi-byte text (a character straddling the cap is dropped whole), or when
it contains U+FFFD. ASCII output under the cap was not cut and gets no
note. The receipt cannot say for certain whether a cut happened (an output
of exactly 65,536 bytes is flagged even if nothing was dropped, and an ASCII
output left short by a dropped multi-byte character is not); the in-band
truncation marker that settles it is a v3 item. Every tool prints the same newline-terminated
`note (unsigned): ...` lines: the MCP server at the end of the result footer,
after the `attestation:` line (so the output bytes and their digest are
unchanged), `verify_receipt`, and `ampoule-verify`, from `--output` or, for
a saved tool result without `--output`, from the output above the footer
(which it then says it did not check). The notes are not signed.
The verifier also reports output that is not valid UTF-8, which this kernel
never produces. When `verify_receipt` or `ampoule-verify` is given a whole
tool result, it takes the `attestation:` line only from the footer (after
the last `\n--\nvm: `). A guest can print its own `attestation:` line in its
output, for example a signed envelope copied from another run, and that line
is ignored. An in-band truncation marker and raw
output bytes need a kernel change (new `kernel_sha256`) and are planned with
the next predicate version.

## Envelope and signing

- `payloadType` is `application/vnd.in-toto+json`; the signature is Ed25519
  over the DSSE pre-authentication encoding
  `DSSEv1 <len(type)> <type> <len(body)> <body>`.
- `keyid` is the lowercase hex SHA-256 of the raw 32-byte public key. As in
  DSSE it is an optional hint: absent, `null` or empty means "try every
  trusted key"; a present value restricts that entry to the key it names.
- The envelope has exactly three top-level fields: `payloadType`,
  `payload` and `signatures`. Any other top-level field makes the receipt
  FAILED (exit 1): these fields are not signed, so an extra one could
  only have been added after signing. `ampoule-verify` prints the reason on
  a `note (unsigned): envelope has N unknown top-level field(s) (first:
  "NAME"); ...` line before an unchanged `result     FAILED` line; `verify
  --replay` refuses it before anything runs (`REPLAY FAILED: receipt does
  not parse strictly`, exit 1, with or without `--key`); the MCP
  `verify_receipt` tool answers `result: FAILED (envelope has an unknown
  field)`.
- Each `signatures[]` entry may carry only `keyid` and `sig`. Any other
  field in any entry, including an entry that would not verify, makes the
  receipt FAILED (exit 1) the same way, with the reason on a
  `note (unsigned): signatures[I] has N unknown field(s) (first: "NAME");
  only keyid and sig are allowed in a signature entry` line. A top-level
  unknown field is reported first.
- An envelope may carry several signatures. Verifiers try every entry
  against every trusted key and accept the envelope when any one verifies
  (a bad or foreign signature in front of a good one does not hide it). A
  `sig` that is not valid standard base64 makes the envelope malformed.
  The verdict comes only from signatures that verify (multi-signature
  rule): the `signature  ok    key ...` line names the first trusted
  key whose signature verified, never a `keyid` hint. Other trusted keys
  whose signatures also verify are named on `note (unsigned): also signed
  by trusted key ...` lines; entries that verify with no trusted key are
  ignored and counted on a `note (unsigned): N of M signatures did not
  verify with any trusted key and were ignored` line, without echoing their
  hints. Two entries from one key count once. Notes come before the result
  line.
- Verification is strict Ed25519 (RFC 8032 with the small-order and
  canonical-encoding checks of ed25519-dalek's `verify_strict`). A weak
  trusted key is refused outright (exit 2): any of the 8 small-order
  points (orders 1, 2, 4, 8; e.g. the identity, `01` followed by 31 zero
  bytes), under which a signature with R = that point and s = 0 satisfies
  the lax equation for any statement, and any non-canonical encoding.
- Ed25519 is deterministic: the same statement and key give byte-identical
  envelopes, so two deterministic runs can be compared as envelopes.
- The host only signs when it has re-hashed the payload and output and they
  match what the guest reported.

## What a signature does and does not prove

It proves that the holder of the key vouched for this run, and that nothing
in the statement changed afterwards. It does not prove that the key holder
was honest, or what hardware ran the VM. That is tamper evidence, not remote
attestation. For deterministic runs the signer does not need to be trusted at
all: anyone with the kernel image, the payload and the seed can re-execute and
compare output digest and fuel (`verify --replay`). Replay needs the exact
kernel named by `kernel_sha256`: receipts produced before Rhai fuel was
recorded (older kernel hash) only replay against their own kernel. Kernels
before `terminated` was added leave the header word zero, so their receipts
never carry the field; the kernel that sets it has a new `kernel_sha256`.
Statements and envelopes are parsed strictly: a duplicate JSON key at any level (for example `terminated` or `predicateType` given twice) makes the receipt FAILED, since the signed bytes must have exactly one meaning.

A receipt with `terminated` present is not replayable (see the field table). Binding the signing key to
a measured kernel through a TEE is future work.

## Trust boundary

A signature proves which host key signed a receipt; it does not prove the host told the truth. Anyone holding the signing key can produce any receipt, including one that drops `terminated` from a run the host killed.

- **Deterministic runs:** replay is the independent check. `verify --replay` with the exact kernel image re-derives the output and fuel; a receipt that does not match is rejected (`REPLAY FAILED: <field> differs from the receipt`, exit 1), as is one whose signature does not verify with the given key (`REPLAY FAILED: signature not valid for this key`, checked before anything is re-run). Only exit 0 prints `REPLAY OK`. Replay detects tampering only when the rerun's output or fuel differs from the receipt (in a downgrade test the output matched and only the fuel differed). Replay checks deterministic runs only, and only when the run ended by fuel, not by the host wall clock; a rerun that itself hits the wall clock is reported as `REPLAY FAILED: rerun hit wall timeout`.
- **Non-deterministic runs:** they cannot be replayed, so the signing key is the entire trust boundary. Protect the key, rotate it, and revoke it on compromise; consumers that log accepted receipts by key can re-flag past acceptances after a revocation.

## v2: differences from v1

v2 exists so that a verifier that only knows v1 fails closed. A v1-only
verifier checks the signature and the predicate type, and would print
VERIFIED for a receipt whose run the host stopped (`terminated`), because v1
never defined that field. Under v2 the same verifier rejects every new
receipt for its unknown predicate type instead.

- **Predicate type** is `https://ampoule.dev/attestation/run/v2`. Every
  receipt signed from v2 on uses it, terminated or not, so the predicate
  type alone never tells a reader whether the run ended normally.
- **`terminated`** (optional) is defined by v2 only; see the field table.
  A v2 verifier must report a receipt carrying it as not replayable, never as
  a pass (`ampoule-verify` and `verify --replay` exit 3).
- **`stop`** (optional) was added to v2 later, without a new predicate
  type (the last such addition: since the closed lists, the v2 list is closed), because it cannot change any earlier verifier's verdict: it is only
  ever written with `status` 1, so a verifier that ignores it (any v2
  verifier before `stop`) still reports RUN FAILED, exit 4, never a pass. It is
  rejected in a v1 statement, like `terminated`.
- **All other fields** (`version` stays `1`, `kernel_sha256`, `vmm`,
  `runtime`, `flags`, `deterministic`, `seed`, `payload_sha256`,
  `output_sha256`, `fuel`, `status`), the subject, the statement and the
  DSSE envelope are unchanged.

What a v2 verifier accepts:

| predicateType | `terminated` absent | `terminated` present |
|---|---|---|
| `.../run/v2` | accepted (VERIFIED, exit 0 with the kernel pinned, INCOMPLETE, exit 5, without; RUN FAILED, exit 4, when `status` ≠ 0) | signature checked, NOT REPLAYABLE (exit 3) |
| `.../run/v1` | accepted (legacy receipt, exit 0 or 5 as for v2; exit 4 when `status` ≠ 0) | **rejected** (FAILED, exit 1): v1 never defined the field |
| anything else | rejected (exit 1) | rejected (exit 1) |

`stop: "fuel"` (v2, `terminated` absent, `status` 1) is RUN FAILED, exit 4,
like the same receipt without it; in a v1 statement it is rejected (exit 1).
In every cell, a predicate field outside the version's closed list is
FAILED, exit 1 (see [Closed field lists](#closed-field-lists)).

### Exit-code change in the hardening release

Deliberate: a receipt whose signed `status` is nonzero (and that has no
`terminated`) used to exit 0 (`VERIFIED`) and now exits 4
(`RUN FAILED: signature valid, status N, meaning (<scope>)`). Nothing else changes exit code
for a receipt that was valid before; receipts that violate the field types
above, or lack `kernel_sha256`, now fail (exit 1), and a missing or
unreadable `--output`/`--payload`/`--kernel` file exits 2 instead of 1:
an I/O problem says nothing about the receipt, so it is a usage/I-O error
like an unreadable ENVELOPE (which was already 2), not FAILED. Every file
is read before any verdict, so 2 outranks 1. Callers that treat
"exit 0 or 3" as "the signature is fine" should add 4. Also new: exit 6
for an input over the 64 MiB cap (nothing verified), `verify --replay`
exits 4 (`REPLAY MATCHED, RUN FAILED`) instead of 0 for a matching replay
of a receipt with a nonzero status, weak (small-order) keys are refused
(exit 2), and an `attestation:` line in text without the MCP footer is
ignored unless it is the whole text.

Also deliberate: exit 5, `INCOMPLETE`. A good receipt (signature valid,
status 0, no `terminated`, every given digest matching) whose kernel was not
pinned (neither `--kernel` nor `--expected-kernel-sha256`) used to exit 0
and now exits 5. Its result line leads with `INCOMPLETE` and never contains
the word `VERIFIED`, so a caller that greps for VERIFIED cannot mistake it
for a pass. It ends with the same scope suffix as NOT REPLAYABLE and RUN
FAILED, then how to pin:

    result     INCOMPLETE: signature valid, kernel not pinned (signature only; output, payload, kernel not checked); pin it with --kernel or --expected-kernel-sha256

The suffix is `(<checked> checked; <unchecked> not checked)`, or
`(signature only; <unchecked> not checked)` when no file was given
(`ampoule-verify` turns a would-be exit 0 without `--payload` into exit 2;
3, 4 and 5 keep this suffix); the unchecked list is always complete, in the
order output, payload, kernel.
Exit 0 means a fully pinned check and its line starts with `VERIFIED`.

The same rule holds for every non-pass verdict: the word `VERIFIED` appears
only in exit 0's line. Verdicts lead with their own word, then `signature
valid` where the signature checked out:

    result     NOT REPLAYABLE: signature valid, terminated=wall_timeout (signature only; output, payload, kernel not checked)
    result     RUN FAILED: signature valid, status 1, program error (payload checked; output, kernel not checked)
    result     INCOMPLETE: signature valid, kernel not pinned (signature only; output, payload, kernel not checked); pin it with --kernel or --expected-kernel-sha256
    result     FAILED

The MCP `verify_receipt` tool ranks its answers the same way:
`INCOMPLETE: signature valid, kernel not pinned (<scope>)` for a good
receipt without `expected_kernel_sha256`, `USAGE: payload not checked
(<scope>)` when only the payload is missing, `PASS: signature valid` when
everything is pinned and matches (never the word VERIFIED), and
`NOT REPLAYABLE: …` / `RUN FAILED: …` / `FAILED (…)` in the same form.
Callers that only want the signature should accept 5 as well.

Precedence when several apply (one function, `attest::exit_code`): 2 (and
6, both decided before any verdict) > 1 FAILED > 3 NOT REPLAYABLE > 4 RUN
FAILED > 5 INCOMPLETE > 0 VERIFIED. So an unpinned check of a failed
run is 4, and an unpinned not-replayable run is 3.

## Verifying

```
ampoule-verify envelope.json (--key <pubkey-hex|file> | --trusted-keys FILE)... \
    [--output F] [--payload F] [--kernel F] [--expected-kernel-sha256 HEX]
cargo run -p verify --release -- --replay envelope.json --key <pubkey> --js code.js
```

The public key is the trust anchor and must reach the verifier by some other
channel than the envelope. `ampoule-verify pubkey` prints the key a host signs with.
