//! Signed run receipts. A receipt from `vmhost::receipt` becomes the predicate
//! of an in-toto Statement v1 whose subject is the output digest; the
//! statement is signed with Ed25519 inside a DSSE envelope, the format
//! in-toto, Sigstore and SLSA tooling already read.
//!
//! The signature says "this host's key vouches that kernel K ran payload P
//! and produced output O". It is tamper evidence plus key identity, not
//! remote attestation: whoever holds the key could sign anything. Re-running
//! a deterministic receipt (`verify --replay`) removes the need to trust the
//! signer at all; the signature is for when re-running is not practical.

use std::fs;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde_json::{json, Value};

pub const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
/// Predicate type of every receipt signed now. The spec is attest/PREDICATE.md.
/// v2 adds the optional `terminated` field; a verifier that only knows v1
/// rejects v2 outright (unknown predicateType) instead of printing VERIFIED.
pub const PREDICATE_TYPE: &str = PREDICATE_TYPE_V2;
pub const PREDICATE_TYPE_V2: &str = "https://ampoule.dev/attestation/run/v2";
/// Permanent: receipts signed before v2 carry it and still verify, but a v1
/// statement must not contain `terminated` (v1 never defined it).
pub const PREDICATE_TYPE_V1: &str = "https://ampoule.dev/attestation/run/v1";
pub const PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    hex(&sha2::Sha256::digest(data))
}

/// Key id: SHA-256 of the raw 32-byte public key, hex.
pub fn keyid(pk: &VerifyingKey) -> String {
    sha256_hex(pk.as_bytes())
}

/// DSSE pre-authentication encoding: what actually gets signed.
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut m = format!("DSSEv1 {} {} {} ", payload_type.len(), payload_type, payload.len()).into_bytes();
    m.extend_from_slice(payload);
    m
}

/// Wrap a receipt as an in-toto Statement. The receipt is the predicate
/// verbatim, so it round-trips for `verify --replay`.
pub fn statement(receipt: &Value) -> Result<Value, String> {
    statement_as(receipt, PREDICATE_TYPE)
}

/// As [`statement`] with an explicit predicate type (tests, legacy v1 fixtures).
pub fn statement_as(receipt: &Value, predicate_type: &str) -> Result<Value, String> {
    let out = receipt["output_sha256"].as_str().ok_or("receipt has no output_sha256")?;
    Ok(json!({
        "_type": STATEMENT_TYPE,
        "subject": [{ "name": "output", "digest": { "sha256": out } }],
        "predicateType": predicate_type,
        "predicate": receipt,
    }))
}

/// Where the host signing key lives: `AMPOULE_SIGNING_KEY`, else
/// `~/.ampoule/signing.key`. `AMPOULE_SIGNING_KEY=off` disables signing.
pub fn default_key_path() -> Option<PathBuf> {
    match std::env::var("AMPOULE_SIGNING_KEY") {
        Ok(v) if matches!(v.as_str(), "off" | "0" | "false" | "") => None,
        Ok(v) => Some(PathBuf::from(v)),
        Err(_) => {
            let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))?;
            Some(Path::new(&home).join(".ampoule").join("signing.key"))
        }
    }
}

pub struct Signer {
    key: SigningKey,
    keyid: String,
}

impl Signer {
    pub fn from_seed(seed: [u8; 32]) -> Signer {
        let key = SigningKey::from_bytes(&seed);
        let keyid = keyid(&key.verifying_key());
        Signer { key, keyid }
    }

    /// Load a hex-encoded 32-byte seed, or create one (mode 0600 on Unix)
    /// with its public key beside it as `<path>.pub`. Returns whether it was created.
    pub fn load_or_create(path: &Path) -> std::io::Result<(Signer, bool)> {
        if let Ok(text) = fs::read_to_string(path) {
            let seed: [u8; 32] = unhex(&text)
                .and_then(|b| b.try_into().ok())
                .ok_or_else(|| std::io::Error::other(format!("{} is not a hex Ed25519 seed", path.display())))?;
            return Ok((Signer::from_seed(seed), false));
        }
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).map_err(|e| std::io::Error::other(e.to_string()))?;
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
        std::io::Write::write_all(&mut opts.open(path)?, format!("{}\n", hex(&seed)).as_bytes())?;
        let signer = Signer::from_seed(seed);
        let mut pub_path = path.as_os_str().to_owned();
        pub_path.push(".pub");
        fs::write(pub_path, format!("{}\n", signer.public_hex()))?;
        Ok((signer, true))
    }

    pub fn public_hex(&self) -> String {
        hex(self.key.verifying_key().as_bytes())
    }

    pub fn keyid(&self) -> &str {
        &self.keyid
    }

    /// Receipt JSON in, DSSE envelope JSON (one line) out. Ed25519 is
    /// deterministic, so the same run and key give the same envelope bytes.
    pub fn sign_receipt(&self, receipt_json: &str) -> Result<String, String> {
        self.sign_receipt_as(receipt_json, PREDICATE_TYPE)
    }

    /// As [`Signer::sign_receipt`] with an explicit predicate type. Only for
    /// tests and legacy fixtures; production always signs [`PREDICATE_TYPE`].
    pub fn sign_receipt_as(&self, receipt_json: &str, predicate_type: &str) -> Result<String, String> {
        let receipt: Value = serde_json::from_str(receipt_json).map_err(|e| format!("receipt is not JSON: {e}"))?;
        let body = serde_json::to_vec(&statement_as(&receipt, predicate_type)?).map_err(|e| e.to_string())?;
        let sig = self.key.sign(&pae(PAYLOAD_TYPE, &body));
        Ok(json!({
            "payloadType": PAYLOAD_TYPE,
            "payload": b64().encode(&body),
            "signatures": [{ "keyid": self.keyid, "sig": b64().encode(sig.to_bytes()) }],
        })
        .to_string())
    }
}

/// A public key given as 64 hex characters, or a file holding them.
/// Weak keys (small-order points, such as the identity) are rejected: with
/// one, a forged signature verifies on any message (see [`check_key`]).
pub fn parse_public_key(arg: &str) -> Result<VerifyingKey, String> {
    let text = if Path::new(arg).is_file() { fs::read_to_string(arg).map_err(|e| format!("{arg}: {e}"))? } else { arg.to_string() };
    let bytes: [u8; 32] = unhex(&text).and_then(|b| b.try_into().ok()).ok_or("public key must be 64 hex characters")?;
    let pk = VerifyingKey::from_bytes(&bytes).map_err(|e| format!("bad public key: {e}"))?;
    check_key(&pk)?;
    Ok(pk)
}

/// Reject a weak public key: a point of small order (the identity or one of
/// the other 7 torsion points). Nobody holds a secret for such a key, and
/// signatures under it can be forged for any message (R = identity, s = 0
/// verifies against the identity key under non-strict Ed25519).
///
/// A non-canonical encoding (y not reduced mod p, or the sign bit set on
/// x = 0) is rejected too, whatever point it decodes to: a key must have
/// exactly one encoding, so its keyid names exactly one key.
pub fn check_key(pk: &VerifyingKey) -> Result<(), String> {
    if pk.is_weak() {
        return Err(format!("weak public key {} rejected (small-order point; signatures under it can be forged)", hex(pk.as_bytes())));
    }
    if pk.to_edwards().compress().as_bytes() != pk.as_bytes() {
        return Err(format!("weak public key {} rejected (non-canonical encoding)", hex(pk.as_bytes())));
    }
    Ok(())
}

/// Parse JSON strictly: a duplicate object key anywhere (at any depth) is an
/// error. serde_json alone keeps the last value, so `"terminated":"x",
/// "terminated":null` would read as null; signed bytes must mean one thing.
pub fn parse_strict(bytes: &[u8]) -> Result<Value, String> {
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let v = serde::Deserialize::deserialize(&mut de).map(|StrictValue(v)| v).map_err(|e| e.to_string())?;
    de.end().map_err(|e| e.to_string())?;
    Ok(v)
}

struct StrictValue(Value);

impl<'de> serde::Deserialize<'de> for StrictValue {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(StrictVisitor).map(StrictValue)
    }
}

struct StrictVisitor;

impl<'de> serde::de::Visitor<'de> for StrictVisitor {
    type Value = Value;
    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("JSON without duplicate keys")
    }
    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
        Ok(v.into())
    }
    fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
        Ok(v.into())
    }
    fn visit_f64<E>(self, v: f64) -> Result<Value, E> {
        Ok(serde_json::Number::from_f64(v).map(Value::Number).unwrap_or(Value::Null))
    }
    fn visit_str<E>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }
    fn visit_string<E>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }
    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_none<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut a: A) -> Result<Value, A::Error> {
        let mut v = Vec::new();
        while let Some(StrictValue(x)) = a.next_element()? {
            v.push(x);
        }
        Ok(Value::Array(v))
    }
    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut a: A) -> Result<Value, A::Error> {
        let mut m = serde_json::Map::new();
        while let Some(k) = a.next_key::<String>()? {
            let StrictValue(v) = a.next_value()?;
            if m.contains_key(&k) {
                return Err(serde::de::Error::custom(format!("duplicate key {k:?}")));
            }
            m.insert(k, v);
        }
        Ok(Value::Object(m))
    }
}

/// Outcome of a successful signature check. A receipt whose predicate carries
/// a `terminated` key (any value, even null) is never a plain `Verified`, and
/// neither is one whose run reported a nonzero `status`: library users must
/// handle `VerifiedNotReplayable` and `VerifiedRunFailed` explicitly.
#[must_use]
#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    /// Signature, statement and subject check out; the run ended normally
    /// with status 0.
    Verified(Value),
    /// Signature checks out, but the signed receipt says the run was stopped
    /// (e.g. `wall_timeout`), so it is not a replayable pure function.
    /// Takes precedence over a nonzero status (a stopped run's status
    /// describes the stop, not the program).
    VerifiedNotReplayable { statement: Value, reason: String },
    /// Signature checks out and the run ended on its own, but the signed
    /// receipt attests a failed run: `status` is nonzero (an error raised by
    /// the code, a missing runtime, a limit or a fault). The receipt is
    /// genuine; the result it records is a failure, not a success.
    VerifiedRunFailed { statement: Value, status: u64 },
}

impl Verdict {
    pub fn statement(&self) -> &Value {
        match self {
            Verdict::Verified(s) | Verdict::VerifiedNotReplayable { statement: s, .. } | Verdict::VerifiedRunFailed { statement: s, .. } => s,
        }
    }
    pub fn into_statement(self) -> Value {
        match self {
            Verdict::Verified(s) | Verdict::VerifiedNotReplayable { statement: s, .. } | Verdict::VerifiedRunFailed { statement: s, .. } => s,
        }
    }
    /// True only for `Verified`.
    pub fn is_verified(&self) -> bool {
        matches!(self, Verdict::Verified(_))
    }
    pub fn not_replayable_reason(&self) -> Option<&str> {
        match self {
            Verdict::VerifiedNotReplayable { reason, .. } => Some(reason),
            _ => None,
        }
    }
    /// The nonzero status of a `VerifiedRunFailed` verdict.
    pub fn run_failed_status(&self) -> Option<u64> {
        match self {
            Verdict::VerifiedRunFailed { status, .. } => Some(*status),
            _ => None,
        }
    }
}

/// Check the envelope's signature with `pk` and return a verdict that
/// includes the termination and status checks. See [`verify_envelope_keys`].
pub fn verify_envelope(envelope: &Value, pk: &VerifyingKey) -> Result<Verdict, String> {
    verify_envelope_keys(envelope, std::slice::from_ref(pk)).map(|(v, _)| v)
}

/// The only top-level fields a DSSE envelope may carry (attest/PREDICATE.md,
/// "Envelope and signing"). Anything else makes the receipt FAILED.
/// One entry per line: allowing a new envelope field is a one-line change.
/// (This is the unsigned envelope only. Fields of the signed predicate, such
/// as the `stop`, are checked by [`check_predicate`], not here.)
pub const ENVELOPE_FIELDS: &[&str] = &[
    "payloadType",
    "payload",
    "signatures",
];

/// The only fields a `signatures[]` entry may carry (DSSE: an optional
/// `keyid` hint and the `sig`). Anything else makes the receipt FAILED
/// (closed list). One entry per line, like [`ENVELOPE_FIELDS`].
pub const SIGNATURE_FIELDS: &[&str] = &[
    "keyid",
    "sig",
];

/// Refuse an envelope with a top-level field outside [`ENVELOPE_FIELDS`], or
/// a `signatures[]` entry with a field outside [`SIGNATURE_FIELDS`] (
/// option 1). These fields are unsigned, so an unknown one could only have
/// been added after signing; a verifier must not pass it along as part of a
/// verified receipt. Every entry is checked, including ones that would not
/// verify. The reason names the first unknown field through
/// [`text_for_display`], so a crafted name can never add a line or a verdict
/// word to a verifier's output. Entries that are not objects are left to
/// the signature check (already FAILED there).
pub fn check_envelope_fields(envelope: &Value) -> Result<(), String> {
    let env = envelope.as_object().ok_or("envelope is not a JSON object")?;
    let unknown: Vec<&String> = env.keys().filter(|k| !ENVELOPE_FIELDS.contains(&k.as_str())).collect();
    if let Some(first) = unknown.first() {
        return Err(format!(
            "envelope has {} unknown top-level field{} (first: {}); only {} are allowed",
            unknown.len(),
            plural(unknown.len()),
            field_name_for_display(first),
            fields_text(ENVELOPE_FIELDS)
        ));
    }
    if let Some(Value::Array(sigs)) = env.get("signatures") {
        for (i, entry) in sigs.iter().enumerate() {
            let Some(entry) = entry.as_object() else { continue };
            let unknown: Vec<&String> = entry.keys().filter(|k| !SIGNATURE_FIELDS.contains(&k.as_str())).collect();
            if let Some(first) = unknown.first() {
                return Err(format!(
                    "signatures[{i}] has {} unknown field{} (first: {}); only {} are allowed in a signature entry",
                    unknown.len(),
                    plural(unknown.len()),
                    field_name_for_display(first),
                    fields_text(SIGNATURE_FIELDS)
                ));
            }
        }
    }
    Ok(())
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

/// "payloadType, payload and signatures": a field list as prose.
fn fields_text(fields: &[&str]) -> String {
    match fields.split_last() {
        Some((last, rest)) if !rest.is_empty() => format!("{} and {last}", rest.join(", ")),
        Some((last, _)) => last.to_string(),
        None => String::new(),
    }
}

/// Everything [`verify_envelope_detail`] learned about the signatures.
#[derive(Debug)]
pub struct EnvelopeCheck {
    pub verdict: Verdict,
    /// Index into the trusted keys of the first signature that verified.
    pub key: usize,
    /// Other trusted keys (indices, distinct, in signature order) whose
    /// signature also verified. Only keys that verified are ever listed.
    pub also_verified: Vec<usize>,
    /// Signature entries that did not verify against any trusted key and were
    /// ignored. Their keyid hints are never echoed.
    pub ignored: usize,
    /// Total signature entries in the envelope.
    pub total: usize,
}

/// Check the envelope against a list of trusted keys; returns the verdict and
/// the index of the key whose signature verified.
///
/// DSSE: every entry of `signatures` is tried against every trusted key; the
/// envelope is accepted when any one verifies. `keyid` is an optional hint:
/// absent, null or empty means "try every key"; otherwise the entry is only
/// tried with the key whose id (lowercase hex SHA-256 of the raw public key)
/// it names. A `sig` that is not valid standard base64 makes the envelope
/// malformed (FAILED); one of the wrong length simply does not verify.
/// A top-level field outside [`ENVELOPE_FIELDS`] is FAILED.
///
/// The statement is then parsed strictly (duplicate keys fail) and checked
/// against the predicate spec (attest/PREDICATE.md): every field present
/// with its exact type, known values only, exactly one subject whose digest
/// equals `output_sha256`.
pub fn verify_envelope_keys(envelope: &Value, keys: &[VerifyingKey]) -> Result<(Verdict, usize), String> {
    verify_envelope_detail(envelope, keys).map(|c| (c.verdict, c.key))
}

/// [`verify_envelope_keys`] with the multi-signature details (spec §2.4 step 9,
/// closed lists): the verdict comes only from signatures that verify against a trusted
/// key, identified by the key that verified, never by the `keyid` hint.
/// Entries that do not verify are ignored and counted; two entries from one
/// key count once.
pub fn verify_envelope_detail(envelope: &Value, keys: &[VerifyingKey]) -> Result<EnvelopeCheck, String> {
    verify_envelope_checked(envelope, keys).map_err(|e| e.to_string())
}

/// Why [`verify_envelope_checked`] refused an envelope. Tools print
/// [`VerifyError::UnknownPredicateFields`] as a `note (unsigned): ...` line
/// before `result FAILED`, like an unknown envelope field; every other
/// reason keeps its existing wording. `Display` gives the reason text, the
/// same string [`verify_envelope_detail`] returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// Any other failure (signature, parsing, field types, subject, ...).
    Failed(String),
    /// The signature verified and every existing check passed, but the
    /// signed predicate has a field outside its version's closed list
    /// ([`PREDICATE_FIELDS_V1`], [`PREDICATE_FIELDS_V2`]). Already escaped.
    UnknownPredicateFields(String),
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::Failed(e) | VerifyError::UnknownPredicateFields(e) => f.write_str(e),
        }
    }
}

impl From<String> for VerifyError {
    fn from(e: String) -> Self {
        VerifyError::Failed(e)
    }
}

impl From<&str> for VerifyError {
    fn from(e: &str) -> Self {
        VerifyError::Failed(e.into())
    }
}

/// [`verify_envelope_detail`] with the reason typed, so a tool can tell an
/// unknown predicate field from every other failure.
pub fn verify_envelope_checked(envelope: &Value, keys: &[VerifyingKey]) -> Result<EnvelopeCheck, VerifyError> {
    if keys.is_empty() {
        return Err("no trusted key given".into());
    }
    // Library callers can build a VerifyingKey without parse_public_key.
    for pk in keys {
        check_key(pk)?;
    }
    let env = envelope.as_object().ok_or("envelope is not a JSON object")?;
    check_envelope_fields(envelope)?;
    match env.get("payloadType") {
        Some(Value::String(t)) if t == PAYLOAD_TYPE => {}
        _ => return Err(format!("payloadType is not {PAYLOAD_TYPE}").into()),
    }
    let body = b64().decode(env.get("payload").and_then(Value::as_str).ok_or("envelope has no payload string")?).map_err(|e| format!("payload: {e}"))?;
    let sigs = match env.get("signatures") {
        Some(Value::Array(a)) if !a.is_empty() => a,
        _ => return Err("envelope has no signatures (a non-empty array is required)".into()),
    };
    let ids: Vec<String> = keys.iter().map(keyid).collect();
    let msg = pae(PAYLOAD_TYPE, &body);
    let (mut verified, mut ignored, mut tried) = (Vec::<usize>::new(), 0usize, false);
    for (i, s) in sigs.iter().enumerate() {
        let s = s.as_object().ok_or_else(|| format!("signatures[{i}] is not an object"))?;
        let sig_b64 = s.get("sig").and_then(Value::as_str).ok_or_else(|| format!("signatures[{i}] has no sig string"))?;
        let raw = b64().decode(sig_b64).map_err(|_| format!("signatures[{i}].sig is not valid standard base64"))?;
        let hint = match s.get("keyid") {
            None | Some(Value::Null) => None,
            Some(Value::String(k)) if k.is_empty() => None,
            Some(Value::String(k)) => Some(k.as_str()),
            Some(_) => return Err(format!("signatures[{i}].keyid is not a string").into()),
        };
        let mut hit = None;
        for (k, pk) in keys.iter().enumerate() {
            if hint.is_some_and(|h| h != ids[k]) {
                continue;
            }
            tried = true;
            let Ok(bytes) = <[u8; 64]>::try_from(raw.as_slice()) else { continue };
            // Strict: rejects small-order R and A and non-canonical encodings,
            // so a forged signature under a weak key never verifies.
            if pk.verify_strict(&msg, &Signature::from_bytes(&bytes)).is_ok() {
                hit = Some(k);
                break;
            }
        }
        match hit {
            Some(k) if !verified.contains(&k) => verified.push(k),
            Some(_) => {}
            None => ignored += 1,
        }
    }
    let Some(&k) = verified.first() else {
        return Err(VerifyError::Failed(match (tried, keys.len()) {
            (true, _) => "signature does not verify".into(),
            (false, 1) => "no signature from this key".into(),
            (false, _) => "no signature from any trusted key".into(),
        }));
    };
    let stmt = parse_strict(&body).map_err(|e| format!("statement is not strict JSON: {e}"))?;
    let verdict = check_statement_checked(stmt)?;
    Ok(EnvelopeCheck { verdict, key: k, also_verified: verified[1..].to_vec(), ignored, total: sigs.len() })
}

/// Unsigned note lines (without [`NOTE_PREFIX`]) about the signatures of a
/// verified envelope: other trusted keys that also signed, named only by the
/// key that verified, and entries that did not verify and were ignored.
/// Empty for the usual single-signature receipt.
pub fn signature_note_lines(c: &EnvelopeCheck, keys: &[VerifyingKey]) -> Vec<String> {
    let mut out = Vec::new();
    for &j in &c.also_verified {
        let which = if keys.len() > 1 { format!(" (trusted key {} of {})", j + 1, keys.len()) } else { String::new() };
        out.push(format!("also signed by trusted key {}{which}", &keyid(&keys[j])[..16]));
    }
    if c.ignored > 0 {
        out.push(format!(
            "{} of {} signatures did not verify with any trusted key and were ignored (their keyid hints are not trusted or shown)",
            c.ignored, c.total
        ));
    }
    out
}

/// Statement-level checks after the signature: `_type`, predicate type,
/// predicate fields, subject. Returns the verdict.
pub fn check_statement(stmt: Value) -> Result<Verdict, String> {
    check_statement_checked(stmt).map_err(|e| e.to_string())
}

/// [`check_statement`] with the reason typed (see [`VerifyError`]).
pub fn check_statement_checked(stmt: Value) -> Result<Verdict, VerifyError> {
    if !stmt.is_object() {
        return Err("statement is not a JSON object".into());
    }
    if stmt["_type"].as_str() != Some(STATEMENT_TYPE) {
        return Err(format!("_type is not {STATEMENT_TYPE}").into());
    }
    check_predicate_type(&stmt)?;
    let p = stmt.get("predicate").and_then(Value::as_object).ok_or("predicate is missing or not an object")?;
    check_predicate(p)?;
    // The closed field list runs AFTER the existing checks (types,
    // v1 `terminated`/`stop`, the `stop` rules), so a receipt those already
    // refuse keeps its reason; it only adds a refusal for other fields.
    check_predicate_fields(stmt["predicateType"].as_str(), p).map_err(VerifyError::UnknownPredicateFields)?;
    let subject = match stmt.get("subject") {
        Some(Value::Array(a)) if a.len() == 1 => &a[0],
        _ => return Err("subject must be an array with exactly one entry".into()),
    };
    let digest = subject.get("digest").and_then(|d| d.get("sha256")).and_then(Value::as_str);
    if digest.is_none() || digest != p["output_sha256"].as_str() {
        return Err("subject digest does not match the predicate's output_sha256".into());
    }
    let status = p["status"].as_u64().unwrap_or(u64::MAX);
    let predicate = &stmt["predicate"];
    Ok(match not_replayable_reason(predicate) {
        Some(reason) => Verdict::VerifiedNotReplayable { statement: stmt, reason },
        None if status != 0 => Verdict::VerifiedRunFailed { statement: stmt, status },
        None => Verdict::Verified(stmt),
    })
}

/// Receipt `version` every v1 and v2 predicate carries. Fixed: a different
/// value (or type) is rejected, not read as a newer format.
pub const RECEIPT_VERSION: u64 = 1;
pub const VMMS: [&str; 2] = ["qemu", "firecracker"];
pub const RUNTIMES: [&str; 4] = ["rhai", "wasm", "js", "python"];

fn is_sha256_hex(v: &Value) -> bool {
    v.as_str().is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
}

/// Strict predicate check (attest/PREDICATE.md, v1 and v2): every field is
/// required (`kernel_sha256` included) with its exact JSON type, unknown
/// values are rejected, and `flags`' deterministic bit must agree with
/// `deterministic`. Fields outside the closed list of the predicate version
/// are refused by [`check_predicate_fields`], which runs after this;
/// v1 must not carry `terminated` or `stop` (see [`check_predicate_type`]). `terminated` itself may hold any value: its
/// presence alone makes the receipt not replayable (fail closed). `stop`
/// may only be `"fuel"`, with status 1 and no `terminated` (see
/// [`check_stop`]).
pub fn check_predicate(p: &serde_json::Map<String, Value>) -> Result<(), String> {
    let field = |name: &str| p.get(name).filter(|v| !v.is_null()).ok_or_else(|| format!("predicate.{name} is missing or null"));
    let uint = |name: &str| -> Result<u64, String> { field(name)?.as_u64().ok_or_else(|| format!("predicate.{name} is not an unsigned 64-bit integer")) };
    let version = field("version")?;
    if version.as_u64() != Some(RECEIPT_VERSION) {
        return Err(format!("predicate.version is {}, not {RECEIPT_VERSION}", value_for_display(version)));
    }
    for f in ["kernel_sha256", "payload_sha256", "output_sha256"] {
        if !is_sha256_hex(field(f)?) {
            return Err(format!("predicate.{f} is not 64 lowercase hex characters"));
        }
    }
    let vmm = field("vmm")?;
    if !vmm.as_str().is_some_and(|v| VMMS.contains(&v)) {
        return Err(format!("predicate.vmm is {}, not one of {}", value_for_display(vmm), VMMS.join(", ")));
    }
    let runtime = field("runtime")?;
    if !runtime.as_str().is_some_and(|v| RUNTIMES.contains(&v)) {
        return Err(format!("predicate.runtime is {}, not one of {}", value_for_display(runtime), RUNTIMES.join(", ")));
    }
    let deterministic = field("deterministic")?.as_bool().ok_or("predicate.deterministic is not a boolean")?;
    let flags = uint("flags")?;
    for f in ["seed", "fuel", "status"] {
        uint(f)?;
    }
    if (flags & 0x100 != 0) != deterministic {
        return Err(format!("predicate.flags {flags:#x} deterministic bit disagrees with deterministic={deterministic}"));
    }
    check_stop(p)
}

/// The one value `stop` may hold: the run used up its fuel budget
/// (wasmi fuel for wasm, js and python; the operations limit for rhai).
pub const STOP_FUEL: &str = "fuel";

/// `stop` is optional (absent on every receipt from a kernel before `stop` existed and
/// on every run that did not exhaust its fuel). When present it must be the
/// string `"fuel"`, the run's `status` must be 1 (a fuel stop is a program
/// error to the kernel), and `terminated` must be absent (the guest records
/// one or the other). Anything else is a malformed receipt (FAILED, exit 1),
/// never printed as it is, so a signed `stop` cannot add a line or a
/// verdict word to any tool's output.
fn check_stop(p: &serde_json::Map<String, Value>) -> Result<(), String> {
    let Some(stop) = p.get("stop") else { return Ok(()) };
    if stop.as_str() != Some(STOP_FUEL) {
        return Err(format!("predicate.stop is {}, not \"{STOP_FUEL}\"", value_for_display(stop)));
    }
    if p.contains_key("terminated") {
        return Err("predicate has both `stop` and `terminated`; a run ends one way".into());
    }
    if p.get("status").and_then(Value::as_u64) != Some(1) {
        return Err(format!("predicate.stop is \"{STOP_FUEL}\" but status is {}, not 1", value_for_display(&p["status"])));
    }
    Ok(())
}

/// The closed list of fields a `run/v1` predicate may carry (
/// attest/PREDICATE.md). Anything else is FAILED; v1 is frozen. One entry per
/// line, like [`ENVELOPE_FIELDS`].
pub const PREDICATE_FIELDS_V1: &[&str] = &[
    "version",
    "kernel_sha256",
    "vmm",
    "runtime",
    "flags",
    "deterministic",
    "seed",
    "payload_sha256",
    "output_sha256",
    "fuel",
    "status",
];

/// The closed list of fields a `run/v2` predicate may carry: the v1
/// fields plus `terminated` and the `stop`. Anything else is FAILED,
/// whatever the status. A new field needs a new predicate version (`/v3`),
/// never an entry added here.
pub const PREDICATE_FIELDS_V2: &[&str] = &[
    "version",
    "kernel_sha256",
    "vmm",
    "runtime",
    "flags",
    "deterministic",
    "seed",
    "payload_sha256",
    "output_sha256",
    "fuel",
    "status",
    "terminated",
    "stop",
];

/// The closed field list for a predicate type: v1's for `run/v1`, v2's
/// otherwise (a bare receipt with no statement around it, as `verify
/// --replay` accepts, is checked against v2's, the widest list).
pub fn predicate_fields(predicate_type: Option<&str>) -> (&'static str, &'static [&'static str]) {
    match predicate_type {
        Some(PREDICATE_TYPE_V1) => ("run/v1", PREDICATE_FIELDS_V1),
        _ => ("run/v2", PREDICATE_FIELDS_V2),
    }
}

/// Refuse a predicate with a field outside its version's closed list
/// (closed list): FAILED, exit 1, whatever the status, `terminated` or `stop`.
/// Field names are case-sensitive (`Stop` is not `stop`). Callers run it
/// after [`check_predicate_type`] and [`check_predicate`], so a v1 statement
/// with `terminated` or `stop` keeps that reason. The reason names the first
/// unknown field through [`text_for_display`], so a crafted name can never
/// add a line or a verdict word to a verifier's output.
pub fn check_predicate_fields(predicate_type: Option<&str>, p: &serde_json::Map<String, Value>) -> Result<(), String> {
    let (version, allowed) = predicate_fields(predicate_type);
    let unknown: Vec<&String> = p.keys().filter(|k| !allowed.contains(&k.as_str())).collect();
    match unknown.first() {
        None => Ok(()),
        Some(first) => Err(format!(
            "predicate has {} unknown field{} (first: {}); a {version} predicate allows only {} (a new field needs a new predicate version)",
            unknown.len(),
            plural(unknown.len()),
            field_name_for_display(first),
            fields_text(allowed)
        )),
    }
}

/// True when the (already checked) predicate records a fuel stop: the run
/// used up its fuel budget, a runaway rather than a crash. Such a run
/// is deterministic and replayable; its verdict is the status verdict (RUN
/// FAILED, exit 4), with this as a detail line.
pub fn fuel_stop(predicate: &Value) -> bool {
    predicate.get("stop").and_then(Value::as_str) == Some(STOP_FUEL)
}

/// The detail every tool prints for a receipt with `stop: fuel` (not a
/// verdict line, and never containing a verdict word).
pub const FUEL_STOP_DETAIL: &str = "fuel: the run used up its fuel budget (signed `stop`), so it is a runaway, not a crash";

/// Accept v2, or v1 without `terminated` or `stop`. A v1 statement carrying
/// `terminated` is malformed (v1 never defined the field, and a v1-only
/// verifier would have reported it VERIFIED), so it is rejected; `stop`
///  is v2 only too, since no v1 kernel ever wrote it.
pub fn check_predicate_type(stmt: &Value) -> Result<(), String> {
    match stmt["predicateType"].as_str() {
        Some(PREDICATE_TYPE_V2) => Ok(()),
        Some(PREDICATE_TYPE_V1) => {
            if stmt["predicate"].get("terminated").is_some() {
                Err(format!("predicateType {PREDICATE_TYPE_V1} does not allow `terminated`; such receipts must be {PREDICATE_TYPE_V2}"))
            } else if stmt["predicate"].get("stop").is_some() {
                Err(format!("predicateType {PREDICATE_TYPE_V1} does not allow `stop`; such receipts must be {PREDICATE_TYPE_V2}"))
            } else {
                Ok(())
            }
        }
        _ => Err(format!("predicateType is not {PREDICATE_TYPE_V2} or {PREDICATE_TYPE_V1}")),
    }
}

/// Exit code for a receipt whose signature (and any given hashes) check out
/// but whose run cannot be replayed, e.g. `"terminated": "wall_timeout"`.
/// Used by `ampoule-verify` and `verify --replay`; never a pass.
pub const EXIT_NOT_REPLAYABLE: i32 = 3;

/// Exit code for a receipt whose signature (and any given hashes) check out
/// but whose signed `status` is nonzero: a genuine receipt of a failed run.
/// Used by `ampoule-verify`; never a pass. `terminated` (exit 3) outranks it.
pub const EXIT_RUN_FAILED: i32 = 4;

/// Exit code for a receipt whose signature is valid, status 0, nothing
/// failed, but the check was not fully pinned: the kernel was not checked
/// (neither `--kernel` nor `--expected-kernel-sha256`). Never a full pass;
/// the result line says what went unchecked. 3 and 4 outrank it.
pub const EXIT_SCOPE_INCOMPLETE: i32 = 5;

/// What a finished check found, for [`exit_code`].
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct CheckResult {
    /// Signature, statement, predicate or a given digest/pin failed.
    pub failed: bool,
    /// The signed receipt has `terminated` (any value).
    pub not_replayable: bool,
    /// The signed `status` is nonzero.
    pub run_failed: bool,
    /// The kernel was pinned (by file or digest) and matched.
    pub kernel_pinned: bool,
}

/// The one place that ranks verdicts. When several apply the most serious
/// wins: 2 (usage/I-O, and 6, input too large: both decided before any
/// verdict) > 1 FAILED > 3 NOT REPLAYABLE > 4 RUN FAILED > 5 SCOPE
/// INCOMPLETE > 0 VERIFIED. So an unpinned check of a failed run is 4, and
/// an unpinned not-replayable run is 3.
pub fn exit_code(r: CheckResult) -> i32 {
    if r.failed {
        1
    } else if r.not_replayable {
        EXIT_NOT_REPLAYABLE
    } else if r.run_failed {
        EXIT_RUN_FAILED
    } else if !r.kernel_pinned {
        EXIT_SCOPE_INCOMPLETE
    } else {
        0
    }
}

/// Exit code when an input file (ENVELOPE, stdin, --output, --payload,
/// --trusted-keys, or the receipt given to `verify --replay`) is larger
/// than [`MAX_INPUT_BYTES`]. Nothing is verified; never a pass.
pub const EXIT_INPUT_TOO_LARGE: i32 = 6;

/// Largest input the verifiers read: 64 MiB. Real inputs are far smaller: a
/// signed receipt is about 1-2 KiB, a whole MCP tool result at most the
/// 64 KiB output cap plus its footer, a payload at most the 512 KiB mailbox.
/// The kernel ELF (`--kernel`, about 56 MB with debug info) is hashed as a
/// stream and is not subject to this cap.
pub const MAX_INPUT_BYTES: u64 = 64 << 20;

/// Why [`read_capped`] failed.
#[derive(Debug)]
pub enum ReadError {
    /// More than [`MAX_INPUT_BYTES`]; reading stopped there.
    TooLarge,
    Io(std::io::Error),
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ReadError::TooLarge => write!(f, "larger than the {} MiB input limit", MAX_INPUT_BYTES >> 20),
            ReadError::Io(e) => write!(f, "{e}"),
        }
    }
}

/// Read at most [`MAX_INPUT_BYTES`] from `r`; more is [`ReadError::TooLarge`]
/// (never more than the cap plus one byte is held in memory).
pub fn read_capped(r: impl std::io::Read) -> Result<Vec<u8>, ReadError> {
    let mut buf = Vec::new();
    std::io::Read::read_to_end(&mut r.take(MAX_INPUT_BYTES + 1), &mut buf).map_err(ReadError::Io)?;
    if buf.len() as u64 > MAX_INPUT_BYTES {
        return Err(ReadError::TooLarge);
    }
    Ok(buf)
}

/// [`read_capped`] on a file.
pub fn read_file_capped(path: impl AsRef<Path>) -> Result<Vec<u8>, ReadError> {
    read_capped(fs::File::open(path).map_err(ReadError::Io)?)
}

/// SHA-256 (hex) of a file, read as a stream (no size cap, constant memory).
pub fn sha256_file_hex(path: impl AsRef<Path>) -> std::io::Result<String> {
    use sha2::Digest;
    let mut f = fs::File::open(path)?;
    let mut h = sha2::Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = std::io::Read::read(&mut f, &mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex(&h.finalize()))
}

/// Bytes of program output the guest keeps (`kernel/src/output.rs` CAP).
/// Kernels up to and including the v2 ones cut longer output here without
/// any marker. A cut of ASCII text always leaves exactly `OUTPUT_CAP`
/// bytes; only a multi-byte UTF-8 character straddling the cap can leave 1
/// to 3 bytes free (the kernel backs off to a character boundary). The
/// receipt does not say whether a cut happened; the in-band marker is a v3
/// item. See [`output_notes`] for how that is reported.
pub const OUTPUT_CAP: usize = 64 * 1024;

/// Notes about output bytes that hash correctly but may not be what the
/// program wrote: at the 64 KiB cap (possibly cut, and a stop line the kernel
/// appends may be gone), U+FFFD present (the kernel replaces invalid UTF-8
/// written by Wasm/JS/Python programs before hashing), or not UTF-8 at all.
/// Informational; the signed digest still covers exactly these bytes.
pub fn output_notes(output: &[u8]) -> Vec<String> {
    let mut notes = Vec::new();
    // Exactly at the cap: the output filled it, so it was cut unless the
    // program wrote exactly that many bytes. 1-3 bytes short: a cut is only
    // possible when a multi-byte character straddled the cap, so flag it
    // only when the output has multi-byte text at all. Plain ASCII output
    // under the cap was not cut and gets no note.
    let short = OUTPUT_CAP.saturating_sub(output.len());
    if short == 0 {
        notes.push(format!(
            "output is {} bytes, exactly the {} KiB output cap: it was cut off unless the program wrote exactly that much, \
             and a stop line the kernel appends (\"!! ...\") may be missing; rely on the signed status, not on the text",
            output.len(),
            OUTPUT_CAP >> 10
        ));
    } else if short <= 3 && !output.is_ascii() {
        notes.push(format!(
            "output is {} bytes, {short} short of the {} KiB output cap, with multi-byte text: it was cut off if the next \
             character did not fit (the kernel cuts at a character boundary), and a stop line (\"!! ...\") may be missing; \
             rely on the signed status, not on the text",
            output.len(),
            OUTPUT_CAP >> 10
        ));
    }
    match std::str::from_utf8(output) {
        Ok(t) if t.contains('\u{FFFD}') => notes.push(
            "output contains U+FFFD: the kernel replaces invalid UTF-8 a Wasm, JS or Python program writes with U+FFFD \
             before hashing, so these may not be the bytes the program wrote"
                .into(),
        ),
        Ok(_) => {}
        Err(_) => notes.push("output is not valid UTF-8 (this kernel never produces that); a text view of it is lossy".into()),
    }
    notes
}

/// What a receipt's `status` means. It is the kernel's result code for the
/// run, not the program's exit code: any nonzero exit (Python `sys.exit(2)`,
/// an uncaught exception, which CPython turns into exit 1, or a WASI
/// `proc_exit(N)`) is status 1, and the program's own code appears in the
/// output as the kernel's `!! exit code N` line.
pub fn status_meaning(status: u64) -> &'static str {
    match status {
        0 => "ok",
        1 => "program error: an uncaught exception, a nonzero exit (the code is in the output's `!! exit code N` line), a trap or a limit",
        2 => "bad request or runtime unavailable",
        _ => "limit or fault",
    }
}

/// Short label for a status, for the MCP result footer's `vm:` line:
/// `status 1 (program error)`.
pub fn status_label(status: u64) -> String {
    format!("status {status} ({})", status_short(status))
}

/// A status in a verdict line (RUN FAILED, REPLAY MATCHED, RUN FAILED):
/// `status 1, program error`, with no brackets, so the only brackets after a
/// verdict are its scope (earlier: `status 1 (program error) (<scope>)` was two
/// brackets in a row).
pub fn status_verdict(status: u64) -> String {
    format!("status {status}, {}", status_short(status))
}

fn status_short(status: u64) -> &'static str {
    let m = status_meaning(status);
    m.split(':').next().unwrap_or(m)
}

/// Prefix of every note line any tool prints (ampoule-verify, verify_receipt
/// and the MCP footer): notes about the output bytes and remarks such as the
/// run's status. A note is the printing tool's comment, never part of the
/// signed statement, hence "unsigned" (earlier: one prefix instead of `note`,
/// `note:` and `note (unsigned):`).
pub const NOTE_PREFIX: &str = "note (unsigned): ";

/// [`output_notes`] as text: one `note (unsigned): ...` line per note, each
/// ending in `\n`; empty when there is nothing to say. The MCP footer,
/// `verify_receipt` and `ampoule-verify` all print exactly these lines.
pub fn output_note_lines(output: &[u8]) -> String {
    output_notes(output).iter().map(|n| format!("{NOTE_PREFIX}{n}\n")).collect()
}

/// The program output in a saved MCP tool result: everything before the
/// last "\n--\nvm: " footer. None when the text has no footer.
pub fn output_above_footer(text: &str) -> Option<&[u8]> {
    text.rfind("\n--\nvm: ").map(|at| &text.as_bytes()[..at])
}

/// Why a receipt's run is not a replayable pure function, if it says so.
/// The presence of the `terminated` key counts, whatever its value, including
/// null (fail closed): `wall_timeout` means the host wall-clock safety net
/// stopped the guest, which depends on host timing.
pub fn not_replayable_reason(predicate: &Value) -> Option<String> {
    match predicate.get("terminated") {
        None => None,
        Some(Value::Null) => Some("null".into()),
        Some(Value::String(s)) => Some(s.clone()),
        Some(v) => Some(v.to_string()),
    }
}

/// Longest `terminated` reason printed as it is (see [`reason_for_display`]).
pub const REASON_MAX_LEN: usize = 64;

/// What tools print for a non-plain `terminated` reason. It contains a `-`,
/// which a plain reason never does, so it cannot be mistaken for one.
pub const REASON_NON_STANDARD: &str = "non-standard";

/// How every tool prints a `terminated` reason (ampoule-verify, the MCP
/// server's verify_receipt, `verify --replay`). The value is signed but
/// free-form, so whoever holds the key could put a newline and a forged
/// `result     VERIFIED` line, a CR, an ANSI sequence or the bare word
/// VERIFIED into it. Only a plain token of 1 to [`REASON_MAX_LEN`] characters
/// from `[a-z_]` is printed (`wall_timeout`, and `null` for a JSON null);
/// anything else, the empty string included, prints as
/// [`REASON_NON_STANDARD`]. An allowlist, not escaping: an escaped
/// `"VERIFIED"` would still put the word VERIFIED on a non-pass line. The
/// receipt stays not replayable (exit 3) whatever the value.
pub fn reason_for_display(reason: &str) -> &str {
    if !reason.is_empty() && reason.len() <= REASON_MAX_LEN && reason.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') {
        reason
    } else {
        REASON_NON_STANDARD
    }
}

/// Characters that must never reach a terminal or a line splitter as they
/// are, when the text came from a program or a receipt:
/// every C0 control (U+0000-U+001F: NUL, ESC, CR, LF, VT, FF, the
/// U+001C-U+001E separators), DEL (U+007F), every C1 control
/// (U+0080-U+009F, NEL U+0085 included), the Unicode line and paragraph
/// separators U+2028/U+2029 (with LF, CR, VT, FF, U+001C-U+001E and U+0085
/// this is every break Python's `str.splitlines()` knows), and the bidi
/// controls that can reorder what a terminal shows (U+061C, U+200E, U+200F,
/// U+202A-U+202E, U+2066-U+2069).
pub fn must_escape(c: char) -> bool {
    matches!(c, '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{9f}' | '\u{2028}' | '\u{2029}' | '\u{61c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

/// The verdict words a non-pass line must never contain (the conformance
/// invariants: `REPLAY OK` only on exit 0, the word VERIFIED never in
/// `verify`): in text from a program or a receipt their first letter is
/// written as a JSON `\u` escape, so the printed text never contains them
/// and still decodes to the exact original.
const VERDICT_WORDS: [&str; 2] = ["VERIFIED", "REPLAY OK"];

fn escape_into(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if must_escape(c) => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    for w in VERDICT_WORDS {
        if out.contains(w) {
            let first = w.as_bytes()[0];
            *out = out.replace(w, &format!("\\u{:04x}{}", first, &w[1..]));
        }
    }
}

/// Text from a program or a receipt as one JSON string literal, safe to
/// print on a line of a verifier report: quoted, with `"`, `\`, every
/// [`must_escape`] character and the first letter of each verdict word
/// escaped. So no byte of it can end the line, start a new one (for a
/// terminal, `grep` or `str.splitlines()`), move the cursor, recolour or
/// clear what is shown, or reorder it, and the line never contains
/// `REPLAY OK` or VERIFIED. `json.loads` of it gives back the exact text.
pub fn text_for_display(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    escape_into(&mut out, s);
    format!("\"{out}\"")
}

/// Most escaped characters of a receipt-chosen field name an unknown-field
/// note prints.
pub const FIELD_NAME_DISPLAY_MAX: usize = 80;

/// An unknown field name for the `(first: ...)` part of a note: as
/// [`text_for_display`] when its escaped text is at most
/// [`FIELD_NAME_DISPLAY_MAX`] characters; else the longest prefix of whole
/// escape sequences within that many characters, `…` inside the quotes, then
/// ` [field name cut: N characters escaped]` (the same form as
/// the agents adapter, 3ff98aa). A 1 MiB name no longer gives a 1 MiB line.
pub fn field_name_for_display(name: &str) -> String {
    let esc = line_for_display(name);
    let total = esc.chars().count();
    if total <= FIELD_NAME_DISPLAY_MAX {
        return format!("\"{esc}\"");
    }
    let chars: Vec<char> = esc.chars().collect();
    let (mut i, mut cut) = (0usize, 0usize);
    while i < chars.len() {
        let len = match (chars[i], chars.get(i + 1)) {
            ('\\', Some('u')) => 6,
            ('\\', Some(_)) => 2,
            _ => 1,
        };
        if i + len > FIELD_NAME_DISPLAY_MAX {
            break;
        }
        i += len;
        cut = i;
    }
    let short: String = chars[..cut].iter().collect();
    format!("\"{short}…\" [field name cut: {total} characters escaped]")
}

/// [`text_for_display`] without the quotes, for a message that already has
/// a fixed prefix of its own (an error, a guest serial line).
pub fn line_for_display(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    escape_into(&mut out, s);
    out
}

/// A receipt value in a message: a number, `true`/`false` or `null` as
/// JSON, a string through [`text_for_display`], and an array or object
/// only by its kind (its contents are never copied into a message).
pub fn value_for_display(v: &Value) -> String {
    match v {
        Value::String(s) => text_for_display(s),
        Value::Array(_) => "an array".into(),
        Value::Object(_) => "an object".into(),
        v => v.to_string(),
    }
}

/// The type checks [`verify_envelope_checked`] makes on each `signatures[]`
/// entry, without any key: a non-empty array of objects, each
/// with a `sig` string in standard base64 and a `keyid` that is absent,
/// null or a string. Same messages as the signed path, so replay without
/// --key and with it refuse the same malformed entries.
pub fn check_signature_entry_types(envelope: &Value) -> Result<(), String> {
    let sigs = match envelope.get("signatures") {
        Some(Value::Array(a)) if !a.is_empty() => a,
        _ => return Err("envelope has no signatures (a non-empty array is required)".into()),
    };
    for (i, s) in sigs.iter().enumerate() {
        let s = s.as_object().ok_or_else(|| format!("signatures[{i}] is not an object"))?;
        let sig_b64 = s.get("sig").and_then(Value::as_str).ok_or_else(|| format!("signatures[{i}] has no sig string"))?;
        b64().decode(sig_b64).map_err(|_| format!("signatures[{i}].sig is not valid standard base64"))?;
        match s.get("keyid") {
            None | Some(Value::Null) | Some(Value::String(_)) => {}
            Some(_) => return Err(format!("signatures[{i}].keyid is not a string")),
        }
    }
    Ok(())
}

/// The statement inside an envelope, without checking any signature.
/// For re-execution, where the replay itself is the check.
pub fn unverified_statement(envelope: &Value) -> Result<Value, String> {
    check_envelope_fields(envelope)?;
    check_signature_entry_types(envelope)?;
    let body = b64().decode(envelope["payload"].as_str().ok_or("envelope has no payload")?).map_err(|e| format!("payload: {e}"))?;
    parse_strict(&body).map_err(|e| format!("statement is not strict JSON: {e}"))
}

#[cfg(test)]
mod field_name_cap {
    use super::*;

    #[test]
    fn short_names_unchanged() {
        for n in ["x", &"y".repeat(80), "a\"b"] {
            assert_eq!(field_name_for_display(n), text_for_display(n));
        }
    }

    #[test]
    fn never_cuts_inside_an_escape() {
        // \u0001 escapes to 6 characters; 78 + 6 > 80, so it is dropped whole.
        let n = format!("{}{}", "x".repeat(78), "\u{1}".repeat(1000));
        let d = field_name_for_display(&n);
        assert!(d.starts_with(&format!("\"{}…\" [field name cut: {} characters escaped]", "x".repeat(78), 78 + 6000)), "{d}");
        // 74 + 6 = 80 exactly fits, then \n (2) does not.
        let n = format!("{}\u{1}{}", "x".repeat(74), "\n".repeat(500));
        let d = field_name_for_display(&n);
        assert!(d.starts_with(&format!("\"{}\\u0001…\"", "x".repeat(74))), "{d}");
        assert!(!d.contains('\n'));
        // A two-character escape straddling the mark.
        let n = format!("{}\"{}", "x".repeat(79), "z".repeat(10));
        assert!(field_name_for_display(&n).starts_with(&format!("\"{}…\"", "x".repeat(79))));
    }
}

/// Find an envelope in text: a whole JSON document, or the
/// `attestation: {...}` line in the footer the MCP server prints under each
/// result (after the last "\n--\nvm: "). Text that is a single
/// `attestation:` line (the envelope with a prefix) is also accepted. Any
/// other `attestation:` line, above the footer or in multi-line text with
/// no footer, is ignored.
pub fn find_envelope(text: &str) -> Option<Value> {
    // Strict: an envelope with duplicate keys (e.g. two `payload`s) is not found.
    if let Ok(v) = parse_strict(text.trim().as_bytes()) {
        if v.get("payloadType").is_some() {
            return Some(v);
        }
    }
    // In an MCP tool result, only look in the footer (after the last
    // "\n--\nvm: "): the guest output above it can print its own
    // `attestation:` line, for example a validly signed envelope copied from
    // another run, and that must not be verified in place of the real one.
    // Without a footer, the only accepted form is the text being nothing but
    // one `attestation: {...}` line, which is the bare envelope with a
    // prefix. An `attestation:` line among other text without a footer may
    // be program output (saved without the footer, or printed to look like
    // one), so it is not accepted.
    let Some(i) = text.rfind("\n--\nvm: ") else {
        let t = text.trim();
        if t.contains('\n') {
            return None;
        }
        return t.strip_prefix("attestation:").and_then(|j| parse_strict(j.trim().as_bytes()).ok());
    };
    let footer = &text[i..];
    footer.lines().filter_map(|l| l.trim().strip_prefix("attestation:")).find_map(|j| parse_strict(j.trim().as_bytes()).ok())
}

#[cfg(test)]
mod tests {

    /// Envelope strictness and the multi-signature details.
    #[test]
    fn strict_envelope() {
        let a = Signer::from_seed([3; 32]);
        let b = Signer::from_seed([4; 32]);
        let ka = parse_public_key(&a.public_hex()).unwrap();
        let kb = parse_public_key(&b.public_hex()).unwrap();
        let env: Value = serde_json::from_str(&a.sign_receipt(RECEIPT).unwrap()).unwrap();
        assert!(check_envelope_fields(&env).is_ok());
        let mut extra = env.clone();
        extra["extra"] = json!(1);
        let e = verify_envelope(&extra, &ka).unwrap_err();
        assert!(e.contains("unknown top-level field") && e.contains("\"extra\""), "{e}");
        assert!(unverified_statement(&extra).unwrap_err().contains("unknown top-level field"));
        // Signature-entry fields: only keyid and sig, in every entry.
        let mut sx = env.clone();
        sx["signatures"][0]["extra"] = json!(1);
        let e = verify_envelope(&sx, &ka).unwrap_err();
        assert!(e.starts_with("signatures[0] has 1 unknown field (first: \"extra\")"), "{e}");
        assert!(unverified_statement(&sx).unwrap_err().contains("signatures[0] has"));
        // A long unknown field name is cut at 80 escaped characters.
        let mut big = env.clone();
        big[&"A".repeat(1 << 20)] = json!(1);
        let e = check_envelope_fields(&big).unwrap_err();
        assert!(e.len() < 400, "{} chars", e.len());
        assert!(e.contains(&format!("(first: \"{}…\" [field name cut: 1048576 characters escaped]); only", "A".repeat(80))), "{e}");
        // The no-key path checks entry types like the signed path.
        for (mutate, want) in [
            (json!([]), "envelope has no signatures"),
            (json!("x"), "envelope has no signatures"),
            (json!([1]), "signatures[0] is not an object"),
            (json!([{"sig": 5}]), "signatures[0] has no sig string"),
            (json!([{"sig": "!!"}]), "signatures[0].sig is not valid standard base64"),
            (json!([{"sig": "AAAA", "keyid": 3}]), "signatures[0].keyid is not a string"),
        ] {
            let mut e = env.clone();
            e["signatures"] = mutate;
            let err = unverified_statement(&e).unwrap_err();
            assert!(err.starts_with(want), "{err}");
        }
        let mut e = env.clone();
        e["signatures"][0]["keyid"] = Value::Null;
        assert!(unverified_statement(&e).is_ok());
        let mut sx2 = env.clone();
        let mut second = env["signatures"][0].clone();
        second["sig"] = json!(b64().encode([7u8; 64]));
        second["note"] = json!("x");
        sx2["signatures"].as_array_mut().unwrap().push(second);
        assert!(verify_envelope(&sx2, &ka).unwrap_err().starts_with("signatures[1] has 1 unknown field"));
        let mut no_hint = env.clone();
        no_hint["signatures"][0].as_object_mut().unwrap().remove("keyid");
        assert!(check_envelope_fields(&no_hint).is_ok());
        // Bogus extra entry: ignored, counted, never the named key.
        let mut bogus = env.clone();
        let mut entry = env["signatures"][0].clone();
        entry["keyid"] = json!(keyid(&kb));
        entry["sig"] = json!(b64().encode([7u8; 64]));
        bogus["signatures"].as_array_mut().unwrap().insert(0, entry);
        let c = verify_envelope_detail(&bogus, &[kb, ka]).unwrap();
        assert_eq!((c.key, c.also_verified.clone(), c.ignored, c.total), (1, vec![], 1, 2));
        assert!(signature_note_lines(&c, &[kb, ka]).iter().all(|l| !l.contains(&keyid(&kb)[..16])));
        // Extra valid signature from a second trusted key.
        let other: Value = serde_json::from_str(&b.sign_receipt(RECEIPT).unwrap()).unwrap();
        let mut both = env.clone();
        both["signatures"].as_array_mut().unwrap().push(other["signatures"][0].clone());
        let c = verify_envelope_detail(&both, &[ka, kb]).unwrap();
        assert_eq!((c.key, c.also_verified.clone(), c.ignored), (0, vec![1], 0));
        let c = verify_envelope_detail(&both, &[ka]).unwrap();
        assert_eq!((c.key, c.also_verified.clone(), c.ignored), (0, vec![], 1));
        assert!(verify_envelope_detail(&both, &[kb]).unwrap().key == 0);
    }
    use super::*;
    use std::io::Read as _;

    const RECEIPT: &str = r#"{"version":1,"kernel_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","vmm":"qemu","runtime":"js","flags":260,"deterministic":true,"seed":7,"payload_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","output_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","fuel":5,"status":0}"#;

    const TIMEOUT_RECEIPT: &str = r#"{"version":1,"kernel_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","vmm":"qemu","runtime":"python","flags":264,"deterministic":true,"seed":7,"payload_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","output_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","fuel":5,"status":1,"terminated":"wall_timeout"}"#;

    const FUEL_RECEIPT: &str = r#"{"version":1,"kernel_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","vmm":"qemu","runtime":"python","flags":264,"deterministic":true,"seed":7,"payload_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","output_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","fuel":1999999975550,"status":1,"stop":"fuel"}"#;

    /// A fuel stop is a genuine, replayable failed run: RUN FAILED
    /// (exit 4), never NOT REPLAYABLE, with `stop` readable by the tools.
    #[test]
    fn fuel_stop_is_run_failed_not_not_replayable() {
        let s = Signer::from_seed([3; 32]);
        let env: Value = serde_json::from_str(&s.sign_receipt(FUEL_RECEIPT).unwrap()).unwrap();
        let v = verify_envelope(&env, &s.key.verifying_key()).unwrap();
        assert_eq!(v.run_failed_status(), Some(1));
        assert_eq!(v.not_replayable_reason(), None);
        assert!(!v.is_verified());
        assert!(fuel_stop(&v.statement()["predicate"]));
        assert_eq!(not_replayable_reason(&v.statement()["predicate"]), None);
        let r = CheckResult { run_failed: true, kernel_pinned: true, ..Default::default() };
        assert_eq!(exit_code(r), EXIT_RUN_FAILED);
        // A receipt from before `stop` existed has no `stop`.
        assert!(!fuel_stop(&serde_json::from_str::<Value>(RECEIPT).unwrap()));
        assert!(!fuel_stop(&serde_json::from_str::<Value>(TIMEOUT_RECEIPT).unwrap()));
    }

    #[test]
    fn stripping_or_adding_stop_breaks_signature() {
        let s = Signer::from_seed([3; 32]);
        let pk = s.key.verifying_key();
        for (src, edit) in [(FUEL_RECEIPT, "strip"), (FUEL_RECEIPT.replace(",\"stop\":\"fuel\"", "").leak() as &str, "add")] {
            let env: Value = serde_json::from_str(&s.sign_receipt(src).unwrap()).unwrap();
            let mut stmt: Value = serde_json::from_slice(&b64().decode(env["payload"].as_str().unwrap()).unwrap()).unwrap();
            let p = stmt["predicate"].as_object_mut().unwrap();
            if edit == "strip" {
                p.remove("stop");
            } else {
                p.insert("stop".into(), "fuel".into());
            }
            let mut forged = env.clone();
            forged["payload"] = b64().encode(serde_json::to_vec(&stmt).unwrap()).into();
            assert_eq!(verify_envelope(&forged, &pk).unwrap_err(), "signature does not verify", "{edit}");
        }
    }

    /// `stop` is strict: only "fuel", only with status 1, never with
    /// `terminated`, and v2 only. A bad value is FAILED and is echoed only
    /// through value_for_display.
    #[test]
    fn malformed_stop_is_rejected() {
        let s = Signer::from_seed([3; 32]);
        let pk = s.key.verifying_key();
        let base = FUEL_RECEIPT;
        let cases: Vec<(String, &str)> = vec![
            (base.replace("\"stop\":\"fuel\"", "\"stop\":\"wall_timeout\""), "predicate.stop is \"wall_timeout\""),
            (base.replace("\"stop\":\"fuel\"", "\"stop\":\"FUEL\""), "not \"fuel\""),
            (base.replace("\"stop\":\"fuel\"", "\"stop\":\"\""), "not \"fuel\""),
            (base.replace("\"stop\":\"fuel\"", "\"stop\":null"), "predicate.stop is null"),
            (base.replace("\"stop\":\"fuel\"", "\"stop\":1"), "predicate.stop is 1"),
            (base.replace("\"stop\":\"fuel\"", "\"stop\":[\"fuel\"]"), "predicate.stop is an array"),
            (base.replace("\"stop\":\"fuel\"", "\"stop\":\"VERIFIED\\nresult     VERIFIED\""), "\\u0056ERIFIED"),
            (base.replace("\"status\":1", "\"status\":0"), "status is 0, not 1"),
            (base.replace("\"status\":1", "\"status\":2"), "status is 2, not 1"),
            (base.replace("}", ",\"terminated\":\"wall_timeout\"}"), "both `stop` and `terminated`"),
        ];
        for (r, want) in &cases {
            let env: Value = serde_json::from_str(&s.sign_receipt(r).unwrap()).unwrap();
            let e = verify_envelope(&env, &pk).unwrap_err();
            assert!(e.contains(want), "{r}: {e}");
            assert!(!e.contains("VERIFIED"), "{r}: {e}");
        }
        let v1: Value = serde_json::from_str(&s.sign_receipt_as(base, PREDICATE_TYPE_V1).unwrap()).unwrap();
        assert!(verify_envelope(&v1, &pk).unwrap_err().contains("does not allow `stop`"));
    }

    #[test]
    fn wall_timeout_is_signed_and_not_replayable() {
        let s = Signer::from_seed([3; 32]);
        let env: Value = serde_json::from_str(&s.sign_receipt(TIMEOUT_RECEIPT).unwrap()).unwrap();
        let v = verify_envelope(&env, &s.key.verifying_key()).unwrap();
        assert_eq!(v.not_replayable_reason(), Some("wall_timeout"));
        assert!(!v.is_verified());
        let stmt = v.into_statement();
        assert_eq!(stmt["predicate"]["terminated"], "wall_timeout");
        assert_eq!(not_replayable_reason(&stmt["predicate"]).as_deref(), Some("wall_timeout"));
        let normal: Value = serde_json::from_str(RECEIPT).unwrap();
        assert_eq!(not_replayable_reason(&normal), None);
        // Unknown values fail closed too.
        assert!(not_replayable_reason(&serde_json::json!({"terminated": 1})).is_some());
    }

    #[test]
    fn stripping_wall_timeout_breaks_signature() {
        let s = Signer::from_seed([3; 32]);
        let mut env: Value = serde_json::from_str(&s.sign_receipt(TIMEOUT_RECEIPT).unwrap()).unwrap();
        let mut stmt = unverified_statement(&env).unwrap();
        stmt["predicate"].as_object_mut().unwrap().remove("terminated");
        env["payload"] = Value::String(b64().encode(serde_json::to_vec(&stmt).unwrap()));
        assert!(verify_envelope(&env, &s.key.verifying_key()).is_err());
    }

    #[test]
    fn sign_then_verify() {
        let s = Signer::from_seed([7; 32]);
        let env: Value = serde_json::from_str(&s.sign_receipt(RECEIPT).unwrap()).unwrap();
        let pk = parse_public_key(&s.public_hex()).unwrap();
        let v = verify_envelope(&env, &pk).unwrap();
        assert!(matches!(v, Verdict::Verified(_)));
        let stmt = v.statement();
        assert_eq!(stmt["predicate"]["fuel"], 5);
        assert_eq!(stmt["subject"][0]["digest"]["sha256"], "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
    }

    #[test]
    fn new_receipts_are_v2() {
        let s = Signer::from_seed([7; 32]);
        let env: Value = serde_json::from_str(&s.sign_receipt(RECEIPT).unwrap()).unwrap();
        assert_eq!(verify_envelope(&env, &s.key.verifying_key()).unwrap().statement()["predicateType"], PREDICATE_TYPE_V2);
    }

    #[test]
    fn v1_without_terminated_still_verifies() {
        let s = Signer::from_seed([7; 32]);
        let env: Value = serde_json::from_str(&s.sign_receipt_as(RECEIPT, PREDICATE_TYPE_V1).unwrap()).unwrap();
        assert_eq!(verify_envelope(&env, &s.key.verifying_key()).unwrap().statement()["predicateType"], PREDICATE_TYPE_V1);
    }

    #[test]
    fn v1_with_terminated_is_rejected() {
        let s = Signer::from_seed([7; 32]);
        let env: Value = serde_json::from_str(&s.sign_receipt_as(TIMEOUT_RECEIPT, PREDICATE_TYPE_V1).unwrap()).unwrap();
        let e = verify_envelope(&env, &s.key.verifying_key()).unwrap_err();
        assert!(e.contains("does not allow `terminated`"), "{e}");
    }

    #[test]
    fn v1_with_null_terminated_is_rejected_v2_is_not_replayable() {
        let s = Signer::from_seed([7; 32]);
        let r = RECEIPT.replace("\"status\":0}", "\"status\":0,\"terminated\":null}");
        let v1: Value = serde_json::from_str(&s.sign_receipt_as(&r, PREDICATE_TYPE_V1).unwrap()).unwrap();
        assert!(verify_envelope(&v1, &s.key.verifying_key()).unwrap_err().contains("does not allow `terminated`"));
        let v2: Value = serde_json::from_str(&s.sign_receipt(&r).unwrap()).unwrap();
        assert_eq!(verify_envelope(&v2, &s.key.verifying_key()).unwrap().not_replayable_reason(), Some("null"));
    }

    #[test]
    fn duplicate_predicate_type_v2_then_v1_is_rejected() {
        let s = Signer::from_seed([7; 32]);
        let body = format!("{{\"_type\":\"{STATEMENT_TYPE}\",\"subject\":[{{\"name\":\"output\",\"digest\":{{\"sha256\":\"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\"}}}}],\"predicateType\":\"{PREDICATE_TYPE_V2}\",\"predicateType\":\"{PREDICATE_TYPE_V1}\",\"predicate\":{TIMEOUT_RECEIPT}}}");
        let e = verify_envelope(&sign_body(&s, body.as_bytes()), &s.key.verifying_key()).unwrap_err();
        assert!(e.contains("duplicate key"), "{e}");
    }

    #[test]
    fn unknown_predicate_type_is_rejected() {
        let s = Signer::from_seed([7; 32]);
        for t in ["https://ampoule.dev/attestation/run/v3", ""] {
            let env: Value = serde_json::from_str(&s.sign_receipt_as(RECEIPT, t).unwrap()).unwrap();
            assert!(verify_envelope(&env, &s.key.verifying_key()).is_err(), "{t}");
        }
    }

    #[test]
    fn deterministic_envelope() {
        let s = Signer::from_seed([7; 32]);
        assert_eq!(s.sign_receipt(RECEIPT).unwrap(), s.sign_receipt(RECEIPT).unwrap());
    }

    #[test]
    fn tampered_payload_fails() {
        let s = Signer::from_seed([7; 32]);
        let mut env: Value = serde_json::from_str(&s.sign_receipt(RECEIPT).unwrap()).unwrap();
        let forged = RECEIPT.replace("\"fuel\":5", "\"fuel\":6");
        let body = serde_json::to_vec(&statement(&serde_json::from_str(&forged).unwrap()).unwrap()).unwrap();
        env["payload"] = b64().encode(body).into();
        assert!(verify_envelope(&env, &s.key.verifying_key()).is_err());
    }

    #[test]
    fn other_key_fails() {
        let s = Signer::from_seed([7; 32]);
        let env: Value = serde_json::from_str(&s.sign_receipt(RECEIPT).unwrap()).unwrap();
        let other = Signer::from_seed([8; 32]);
        assert!(verify_envelope(&env, &other.key.verifying_key()).is_err());
    }

    #[test]
    fn pae_matches_spec_example() {
        // From the DSSE protocol document.
        assert_eq!(pae("http://example.com/HelloWorld", b"hello world"), b"DSSEv1 29 http://example.com/HelloWorld 11 hello world".to_vec());
    }

    #[test]
    fn finds_envelope_in_mcp_output() {
        let s = Signer::from_seed([7; 32]);
        let text = format!("42\n--\nvm: restored firecracker\nreceipt: {RECEIPT}\nattestation: {}\n", s.sign_receipt(RECEIPT).unwrap());
        assert!(find_envelope(&text).is_some());
    }

    #[test]
    fn envelope_printed_by_the_guest_is_ignored() {
        let s = Signer::from_seed([7; 32]);
        let planted = s.sign_receipt(TIMEOUT_RECEIPT).unwrap();
        let real = s.sign_receipt(RECEIPT).unwrap();
        let text = format!("attestation: {planted}\n--\nvm: restored firecracker\nreceipt: {RECEIPT}\nattestation: {real}");
        let got = find_envelope(&text).unwrap();
        assert_eq!(got, serde_json::from_str::<Value>(&real).unwrap());
        // The footer's own envelope missing: the planted one is not used either.
        let text = format!("attestation: {planted}\n--\nvm: restored firecracker\nreceipt: {RECEIPT}");
        assert!(find_envelope(&text).is_none());        // No footer: an `attestation:` line among other text is not
        // accepted. Text that is only that one line is the bare envelope
        // with a prefix, and is accepted like the bare envelope.
        assert!(find_envelope(&format!("attestation: {planted}\n")).is_some());
        assert!(find_envelope(&format!("attestation: {planted}\nattestation: {real}")).is_none());
        assert!(find_envelope(&format!("42\nattestation: {real}\n")).is_none());
        assert!(find_envelope(&format!("receipt: {RECEIPT}\nattestation: {real}")).is_none());
        // A whole-document envelope still works.
        assert!(find_envelope(&real).is_some());
    }

    /// Sign raw statement bytes (lets tests build payloads serde_json would never emit).
    fn sign_body(s: &Signer, body: &[u8]) -> Value {
        let sig = s.key.sign(&pae(PAYLOAD_TYPE, body));
        json!({ "payloadType": PAYLOAD_TYPE, "payload": b64().encode(body), "signatures": [{ "keyid": s.keyid, "sig": b64().encode(sig.to_bytes()) }] })
    }

    /// Every break Python's str.splitlines() knows, plus CRLF.
    fn py_splitlines(s: &str) -> Vec<&str> {
        s.split(|c| matches!(c, '\n' | '\r' | '\u{b}' | '\u{c}' | '\u{1c}' | '\u{1d}' | '\u{1e}' | '\u{85}' | '\u{2028}' | '\u{2029}')).collect()
    }

    #[test]
    fn display_escapes_every_control_separator_and_bidi_char() {
        // All of C0, DEL, all of C1, U+2028/U+2029, the bidi controls.
        let mut all: Vec<char> = (0u32..=0x1f).chain(0x7f..=0x9f).filter_map(char::from_u32).collect();
        all.extend(['\u{2028}', '\u{2029}', '\u{61c}', '\u{200e}', '\u{200f}', '\u{202a}', '\u{202b}', '\u{202c}', '\u{202d}', '\u{202e}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}']);
        for c in &all {
            assert!(must_escape(*c), "{:04x}", *c as u32);
            let t = format!("a{c}b");
            for shown in [text_for_display(&t), line_for_display(&t)] {
                assert!(shown.chars().all(|x| !must_escape(x)), "U+{:04x} left raw: {shown:?}", *c as u32);
                assert_eq!(py_splitlines(&shown).len(), 1, "U+{:04x} splits: {shown:?}", *c as u32);
            }
        }
        // Printable text, including non-ASCII, is left alone.
        assert_eq!(text_for_display("PAID 42 é ü 漢 🙂"), "\"PAID 42 é ü 漢 🙂\"");
        assert_eq!(text_for_display("a\"b\\c\nd\re\tf\u{1b}[2K\u{0}\u{7f}\u{85}\u{2028}\u{202e}"), "\"a\\\"b\\\\c\\nd\\re\\tf\\u001b[2K\\u0000\\u007f\\u0085\\u2028\\u202e\"");
    }

    #[test]
    fn display_is_exact_json_and_never_shows_a_verdict_word() {
        let nasty = "PAID\n  result        REPLAY OK\r\noverall         PASS\u{2028}result     VERIFIED\u{85}\u{1b}[1A\u{1b}[2K\u{1b}[32mREPLAY OK\u{1b}[0m\rVERIFIEDVERIFIED \\VERIFIED \"REPLAY OK\"\u{0}";
        let shown = text_for_display(nasty);
        // json.loads(shown) == nasty: a JSON string literal of the exact text.
        assert_eq!(serde_json::from_str::<String>(&shown).unwrap(), nasty);
        assert_eq!(serde_json::from_str::<String>(&format!("\"{}\"", line_for_display(nasty))).unwrap(), nasty);
        for t in [&shown, &line_for_display(nasty)] {
            assert!(!t.contains("VERIFIED") && !t.contains("REPLAY OK"), "{t}");
            assert!(!t.contains('\u{1b}') && !t.contains('\r') && !t.contains('\n'), "{t:?}");
            assert_eq!(py_splitlines(t).len(), 1, "{t:?}");
        }
    }

    #[test]
    fn value_for_display_never_copies_raw_receipt_text() {
        assert_eq!(value_for_display(&json!(5280706085u64)), "5280706085");
        assert_eq!(value_for_display(&json!(-1)), "-1");
        assert_eq!(value_for_display(&json!(1.5)), "1.5");
        assert_eq!(value_for_display(&json!(null)), "null");
        assert_eq!(value_for_display(&json!(true)), "true");
        assert_eq!(value_for_display(&json!("5\u{2028}  result        REPLAY OK")), "\"5\\u2028  result        \\u0052EPLAY OK\"");
        assert_eq!(value_for_display(&json!(["VERIFIED"])), "an array");
        assert_eq!(value_for_display(&json!({"a": "\u{85}"})), "an object");
        // check_predicate echoes a bad vmm/runtime/version only through it.
        let mut p: serde_json::Map<String, Value> = serde_json::from_str(r#"{"version":1,"kernel_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","vmm":"qemu","runtime":"python","flags":264,"deterministic":true,"seed":7,"payload_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","output_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","fuel":5,"status":0}"#).unwrap();
        for f in ["vmm", "runtime", "version"] {
            let mut q = p.clone();
            q.insert(f.into(), json!("x\u{2028}result     VERIFIED\u{85}"));
            let e = check_predicate(&q).unwrap_err();
            assert!(!e.contains("VERIFIED") && py_splitlines(&e).len() == 1, "{f}: {e:?}");
        }
        p.insert("vmm".into(), json!("qemu"));
        assert!(check_predicate(&p).is_ok());
    }

    #[test]
    fn reason_for_display_prints_only_plain_tokens() {
        for plain in ["wall_timeout", "null", "a", &"x".repeat(REASON_MAX_LEN)] {
            assert_eq!(reason_for_display(plain), plain);
        }
        let long = "x".repeat(REASON_MAX_LEN + 1);
        for odd in ["", "VERIFIED", "wall_timeout\nresult     VERIFIED", "wall_timeout\rresult     VERIFIED", "\u{1b}[2K", "a b", "{\"why\":\"VERIFIED\"}", "1", "wall-timeout", "Wall_timeout", long.as_str()] {
            assert_eq!(reason_for_display(odd), REASON_NON_STANDARD, "{odd:?}");
        }
        assert!(!REASON_NON_STANDARD.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'), "the marker must not look like a plain reason");
    }

    #[test]
    fn null_terminated_is_not_replayable() {
        assert_eq!(not_replayable_reason(&json!({"terminated": null})).as_deref(), Some("null"));
        let s = Signer::from_seed([3; 32]);
        let r = RECEIPT.replace("\"status\":0}", "\"status\":0,\"terminated\":null}");
        let env: Value = serde_json::from_str(&s.sign_receipt(&r).unwrap()).unwrap();
        match verify_envelope(&env, &s.key.verifying_key()).unwrap() {
            Verdict::VerifiedNotReplayable { reason, .. } => assert_eq!(reason, "null"),
            v => panic!("null terminated must not verify: {v:?}"),
        }
    }

    #[test]
    fn library_verdict_for_terminated_receipt() {
        let s = Signer::from_seed([3; 32]);
        let env: Value = serde_json::from_str(&s.sign_receipt(TIMEOUT_RECEIPT).unwrap()).unwrap();
        let v = verify_envelope(&env, &s.key.verifying_key()).unwrap();
        assert!(matches!(&v, Verdict::VerifiedNotReplayable { reason, .. } if reason == "wall_timeout"));
        assert!(!v.is_verified());
    }

    fn stmt_text(predicate: &str, ptype_twice: bool) -> String {
        let pt = if ptype_twice { format!("\"predicateType\":\"https://example.com/other\",\"predicateType\":\"{PREDICATE_TYPE}\",") } else { format!("\"predicateType\":\"{PREDICATE_TYPE}\",") };
        format!("{{\"_type\":\"{STATEMENT_TYPE}\",\"subject\":[{{\"name\":\"output\",\"digest\":{{\"sha256\":\"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\"}}}}],{pt}\"predicate\":{predicate}}}")
    }

    #[test]
    fn duplicate_keys_are_rejected() {
        let s = Signer::from_seed([3; 32]);
        let pk = s.key.verifying_key();
        let ok = stmt_text(RECEIPT, false);
        assert!(verify_envelope(&sign_body(&s, ok.as_bytes()), &pk).unwrap().is_verified());
        let dup_term = stmt_text(&TIMEOUT_RECEIPT.replace("}", ",\"terminated\":null}"), false);
        let dup_ptype = stmt_text(RECEIPT, true);
        let nested = stmt_text(RECEIPT, false).replace("{\"sha256\":\"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\"}", "{\"sha256\":\"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\",\"sha256\":\"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\"}");
        for (name, body) in [("terminated", dup_term), ("predicateType", dup_ptype), ("nested", nested)] {
            let env = sign_body(&s, body.as_bytes());
            let e = verify_envelope(&env, &pk).expect_err(name);
            assert!(e.contains("duplicate key"), "{name}: {e}");
            assert!(unverified_statement(&env).is_err(), "{name}");
        }
        // Envelope level too.
        let env = s.sign_receipt(RECEIPT).unwrap();
        let dup_env = env.replacen("{", "{\"payloadType\":\"x\",", 1);
        assert!(find_envelope(&dup_env).is_none());
        assert!(parse_strict(br#"{"a":[{"b":1,"b":2}]}"#).is_err());
        assert!(parse_strict(br#"{"a":[{"b":1},{"b":2}]} x"#).is_err());
    }
    #[test]
    fn nonzero_status_is_run_failed_not_verified() {
        let s = Signer::from_seed([7; 32]);
        let r = RECEIPT.replace("\"status\":0}", "\"status\":3}");
        let env: Value = serde_json::from_str(&s.sign_receipt(&r).unwrap()).unwrap();
        let v = verify_envelope(&env, &s.key.verifying_key()).unwrap();
        assert_eq!(v.run_failed_status(), Some(3));
        assert!(!v.is_verified());
        // terminated outranks the status.
        let env: Value = serde_json::from_str(&s.sign_receipt(TIMEOUT_RECEIPT).unwrap()).unwrap();
        assert!(verify_envelope(&env, &s.key.verifying_key()).unwrap().not_replayable_reason().is_some());
    }

    #[test]
    fn strict_predicate_rejects_bad_types_and_unknown_values() {
        let s = Signer::from_seed([7; 32]);
        let pk = s.key.verifying_key();
        let ok: Value = serde_json::from_str(RECEIPT).unwrap();
        let bad: Vec<(&str, Value)> = vec![
            ("kernel_sha256", Value::Null),
            ("kernel_sha256", json!("aa")),
            ("version", json!(2)),
            ("vmm", json!("kvm")),
            ("runtime", json!("echo")),
            ("deterministic", json!("true")),
            ("fuel", json!(1.5)),
            ("seed", json!(-7)),
            ("status", json!("0")),
        ];
        for (f, v) in bad {
            let mut r = ok.clone();
            r[f] = v.clone();
            let env: Value = serde_json::from_str(&s.sign_receipt(&r.to_string()).unwrap()).unwrap();
            let e = verify_envelope(&env, &pk).expect_err(f);
            assert!(e.contains(&format!("predicate.{f}")), "{f}={v}: {e}");
        }
        let mut r = ok.clone();
        r.as_object_mut().unwrap().remove("kernel_sha256");
        let env: Value = serde_json::from_str(&s.sign_receipt(&r.to_string()).unwrap()).unwrap();
        assert!(verify_envelope(&env, &pk).unwrap_err().contains("kernel_sha256"));
    }

    #[test]
    fn any_trusted_key_and_any_signature() {
        let (a, b) = (Signer::from_seed([1; 32]), Signer::from_seed([2; 32]));
        let mut env: Value = serde_json::from_str(&b.sign_receipt(RECEIPT).unwrap()).unwrap();
        let keys = [a.key.verifying_key(), b.key.verifying_key()];
        assert_eq!(verify_envelope_keys(&env, &keys).unwrap().1, 1);
        assert!(verify_envelope_keys(&env, &keys[..1]).is_err());
        assert!(verify_envelope_keys(&env, &[]).is_err());
        // A second, foreign signature in front does not hide the good one.
        let foreign: Value = serde_json::from_str(&a.sign_receipt(&RECEIPT.replace("\"fuel\":5", "\"fuel\":9")).unwrap()).unwrap();
        let mut sigs = foreign["signatures"].as_array().unwrap().clone();
        sigs.extend(env["signatures"].as_array().unwrap().iter().cloned());
        env["signatures"] = Value::Array(sigs);
        assert_eq!(verify_envelope_keys(&env, &keys).unwrap().1, 1);
    }

    #[test]
    fn status_is_explained_not_an_exit_code() {
        assert_eq!(status_label(0), "status 0 (ok)");
        assert_eq!(status_label(1), "status 1 (program error)");
        assert_eq!(status_label(2), "status 2 (bad request or runtime unavailable)");
        assert_eq!(status_label(7), "status 7 (limit or fault)");
        assert_eq!(status_verdict(1), "status 1, program error");
        assert_eq!(status_verdict(2), "status 2, bad request or runtime unavailable");
        assert_eq!(status_verdict(9), "status 9, limit or fault");
        assert!(status_meaning(1).contains("nonzero exit") && status_meaning(1).contains("!! exit code N"));
    }

    #[test]
    fn exit_code_precedence() {
        let r = |failed, not_replayable, run_failed, kernel_pinned| exit_code(CheckResult { failed, not_replayable, run_failed, kernel_pinned });
        // Every combination: the most serious problem wins.
        for nr in [false, true] {
            for rf in [false, true] {
                for kp in [false, true] {
                    assert_eq!(r(true, nr, rf, kp), 1);
                }
            }
        }
        assert_eq!(r(false, true, true, false), 3);
        assert_eq!(r(false, true, false, false), 3, "unpinned not-replayable is 3");
        assert_eq!(r(false, true, true, true), 3);
        assert_eq!(r(false, false, true, false), 4, "unpinned failed run is 4");
        assert_eq!(r(false, false, true, true), 4);
        assert_eq!(r(false, false, false, false), 5);
        assert_eq!(r(false, false, false, true), 0);
    }

    #[test]
    fn read_capped_stops_at_the_limit() {
        let n = MAX_INPUT_BYTES as usize;
        assert_eq!(read_capped(std::io::repeat(b'x').take(n as u64)).unwrap().len(), n);
        assert!(matches!(read_capped(std::io::repeat(b'x').take(n as u64 + 1)), Err(ReadError::TooLarge)));
        assert!(matches!(read_capped(std::io::repeat(b'x')), Err(ReadError::TooLarge)));
    }

    #[test]
    fn output_notes_flag_cap_and_replacement_chars() {
        assert!(output_notes(b"ok\n").is_empty());
        // Real truncation of ASCII always lands exactly on the cap.
        assert_eq!(output_notes(&vec![b'a'; OUTPUT_CAP]).len(), 1);
        assert!(output_notes(&vec![b'a'; OUTPUT_CAP])[0].contains("exactly the 64 KiB output cap"));
        // ASCII 1-3 bytes short was not cut: no note (it used to fire from 65,533).
        for short in 1..=4 {
            assert!(output_notes(&vec![b'a'; OUTPUT_CAP - short]).is_empty(), "{short}");
        }
        // A 3-byte character cut at the cap leaves 65,535 bytes: flagged.
        let cjk = "\u{4e2d}".repeat(OUTPUT_CAP / 3); // 21845 x 3 = 65535 bytes
        assert_eq!(cjk.len(), OUTPUT_CAP - 1);
        let n = output_notes(cjk.as_bytes());
        assert!(n.len() == 1 && n[0].contains("1 short of the 64 KiB output cap"), "{n:?}");
        // Multi-byte text further from the cap: no cap note.
        assert!(output_notes("\u{4e2d}".repeat(OUTPUT_CAP / 3 - 2).as_bytes()).is_empty());
        assert!(output_notes("x\u{FFFD}".as_bytes())[0].contains("U+FFFD"));
        assert!(output_notes(&[0xff, 0xfe])[0].contains("not valid UTF-8"));
    }

    /// The identity point (compressed: 0x01 then 31 zero bytes).
    const IDENTITY: &str = "0100000000000000000000000000000000000000000000000000000000000000";

    /// An envelope "signed" by the identity key: R = identity, s = 0. It
    /// satisfies the non-strict Ed25519 equation for every message.
    fn forged_identity_envelope(receipt: &str) -> Value {
        let body = serde_json::to_vec(&statement(&serde_json::from_str(receipt).unwrap()).unwrap()).unwrap();
        let mut sig = [0u8; 64];
        sig[0] = 1;
        let kid = sha256_hex(&unhex(IDENTITY).unwrap());
        json!({ "payloadType": PAYLOAD_TYPE, "payload": b64().encode(body), "signatures": [{ "keyid": kid, "sig": b64().encode(sig) }] })
    }

    #[test]
    fn weak_keys_are_rejected() {
        // The identity and the other small-order points.
        let small_order = [
            IDENTITY,
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000080",
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        ];
        for k in small_order {
            let e = parse_public_key(k).expect_err(k);
            assert!(e.contains("weak public key"), "{k}: {e}");
        }
        // Non-canonical encodings: of small-order points (y = p, y = p + 1),
        // and of a large-order point (y = 3 + p, canonical form 03 00..00).
        for k in [
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        ] {
            let e = parse_public_key(k).expect_err(k);
            assert!(e.contains("weak public key"), "{k}: {e}");
        }
        assert!(parse_public_key("f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f").unwrap_err().contains("non-canonical"));
        assert!(parse_public_key(&Signer::from_seed([7; 32]).public_hex()).is_ok());
    }

    #[test]
    fn forged_signature_under_identity_key_never_verifies() {
        let env = forged_identity_envelope(RECEIPT);
        let pk = VerifyingKey::from_bytes(&unhex(IDENTITY).unwrap().try_into().unwrap()).unwrap();
        // Sanity: the forgery does satisfy the lax equation, so the test
        // would catch a regression to non-strict verification.
        use ed25519_dalek::Verifier as _;
        let body = b64().decode(env["payload"].as_str().unwrap()).unwrap();
        let mut sig = [0u8; 64];
        sig[0] = 1;
        assert!(pk.verify(&pae(PAYLOAD_TYPE, &body), &Signature::from_bytes(&sig)).is_ok(), "forgery should pass lax verify");
        // A weak key handed straight to the library is refused...
        let e = verify_envelope(&env, &pk).unwrap_err();
        assert!(e.contains("weak public key"), "{e}");
        // ...also when it sits beside a good key in a trusted list.
        let good = Signer::from_seed([7; 32]).key.verifying_key();
        assert!(verify_envelope_keys(&env, &[good, pk]).is_err());
        // And strict verification alone rejects the forged signature.
        assert!(pk.verify_strict(&pae(PAYLOAD_TYPE, &body), &Signature::from_bytes(&sig)).is_err());
    }

    fn signed(s: &Signer, receipt: &str, ptype: &str) -> Value {
        serde_json::from_str(&s.sign_receipt_as(receipt, ptype).unwrap()).unwrap()
    }

    /// The closed predicate field lists. Every field of the spec, and
    /// nothing else; the lists differ by exactly `terminated` and `stop`.
    #[test]
    fn predicate_field_lists_are_the_spec() {
        let v1: Value = serde_json::from_str(RECEIPT).unwrap();
        let mut keys: Vec<&str> = v1.as_object().unwrap().keys().map(String::as_str).collect();
        let mut want = PREDICATE_FIELDS_V1.to_vec();
        keys.sort();
        want.sort();
        assert_eq!(keys, want);
        let extra: Vec<&&str> = PREDICATE_FIELDS_V2.iter().filter(|f| !PREDICATE_FIELDS_V1.contains(f)).collect();
        assert_eq!(extra, [&"terminated", &"stop"]);
        assert!(PREDICATE_FIELDS_V1.iter().all(|f| PREDICATE_FIELDS_V2.contains(f)));
        assert_eq!(predicate_fields(Some(PREDICATE_TYPE_V1)).0, "run/v1");
        assert_eq!(predicate_fields(Some(PREDICATE_TYPE_V2)).0, "run/v2");
    }

    /// An unknown predicate field is FAILED whatever the status:
    /// status 0 (was VERIFIED), status 1 (was RUN FAILED), status 1 with a
    /// valid `stop`, and `terminated` (was NOT REPLAYABLE). The error is
    /// typed, so tools print it as a note line.
    #[test]
    fn unknown_predicate_field_is_failed_whatever_the_status() {
        let s = Signer::from_seed([11; 32]);
        let pk = s.key.verifying_key();
        let cases = [
            (RECEIPT.replace("\"status\":0}", "\"status\":0,\"x\":1}"), "\"x\""),
            (RECEIPT.replace("\"status\":0}", "\"status\":1,\"note\":\"hi\"}"), "\"note\""),
            (FUEL_RECEIPT.replace("\"stop\":\"fuel\"}", "\"stop\":\"fuel\",\"extra\":true}"), "\"extra\""),
            (TIMEOUT_RECEIPT.replace("}", ",\"x\":null}"), "\"x\""),
        ];
        for (r, name) in cases {
            // Without the extra field the same receipt is accepted.
            let env = signed(&s, &r, PREDICATE_TYPE_V2);
            match verify_envelope_checked(&env, &[pk]) {
                Err(VerifyError::UnknownPredicateFields(e)) => {
                    assert!(e.starts_with(&format!("predicate has 1 unknown field (first: {name}); a run/v2 predicate allows only version, ")), "{e}");
                    assert!(e.ends_with("status, terminated and stop (a new field needs a new predicate version)"), "{e}");
                }
                other => panic!("{r}: {other:?}"),
            }
            // The plain API gives the same reason as a string.
            assert!(verify_envelope(&env, &pk).unwrap_err().starts_with("predicate has 1 unknown field"));
        }
        assert!(verify_envelope(&signed(&s, FUEL_RECEIPT, PREDICATE_TYPE_V2), &pk).unwrap().run_failed_status() == Some(1));
        assert!(verify_envelope(&signed(&s, TIMEOUT_RECEIPT, PREDICATE_TYPE_V2), &pk).unwrap().not_replayable_reason().is_some());
        // Two unknown fields: counted, the first (in key order) named.
        let r = RECEIPT.replace("\"status\":0}", "\"status\":0,\"b\":1,\"a\":2}");
        let e = verify_envelope(&signed(&s, &r, PREDICATE_TYPE_V2), &pk).unwrap_err();
        assert!(e.starts_with("predicate has 2 unknown fields (first: \"a\")"), "{e}");
    }

    /// Field names are case-sensitive. `Stop` is not `stop`: a status-0
    /// receipt carrying `"Stop":"fuel"` was VERIFIED (unknown field ignored)
    /// and is now FAILED; `"Terminated"` likewise.
    #[test]
    fn capitalised_stop_is_failed() {
        let s = Signer::from_seed([12; 32]);
        let pk = s.key.verifying_key();
        for (r, name) in [
            (RECEIPT.replace("\"status\":0}", "\"status\":0,\"Stop\":\"fuel\"}"), "\"Stop\""),
            (FUEL_RECEIPT.replace("\"stop\":\"fuel\"}", "\"Stop\":\"fuel\"}"), "\"Stop\""),
            (RECEIPT.replace("\"status\":0}", "\"status\":0,\"Terminated\":\"wall_timeout\"}"), "\"Terminated\""),
        ] {
            match verify_envelope_checked(&signed(&s, &r, PREDICATE_TYPE_V2), &[pk]) {
                Err(VerifyError::UnknownPredicateFields(e)) => assert!(e.contains(&format!("(first: {name})")), "{e}"),
                other => panic!("{r}: {other:?}"),
            }
        }
    }

    /// The closed list runs after the existing checks. A v1 statement
    /// with `terminated` or `stop` keeps its reason (an untyped failure, no
    /// note line); a bad `stop` keeps its own reason; a v1 statement with
    /// another unknown field is refused against the v1 list.
    #[test]
    fn closed_list_runs_after_existing_checks() {
        let s = Signer::from_seed([13; 32]);
        let pk = s.key.verifying_key();
        let e = verify_envelope_checked(&signed(&s, &TIMEOUT_RECEIPT.replace("}", ",\"x\":1}"), PREDICATE_TYPE_V1), &[pk]).unwrap_err();
        assert!(matches!(&e, VerifyError::Failed(m) if m.contains("does not allow `terminated`")), "{e:?}");
        let e = verify_envelope_checked(&signed(&s, FUEL_RECEIPT, PREDICATE_TYPE_V1), &[pk]).unwrap_err();
        assert!(matches!(&e, VerifyError::Failed(m) if m.contains("does not allow `stop`")), "{e:?}");
        let r = FUEL_RECEIPT.replace("\"status\":1,\"stop\":\"fuel\"}", "\"status\":0,\"stop\":\"fuel\",\"x\":1}");
        let e = verify_envelope_checked(&signed(&s, &r, PREDICATE_TYPE_V2), &[pk]).unwrap_err();
        assert!(matches!(&e, VerifyError::Failed(m) if m.contains("but status is 0, not 1")), "{e:?}");
        let r = RECEIPT.replace("\"status\":0}", "\"status\":0,\"x\":1}");
        match verify_envelope_checked(&signed(&s, &r, PREDICATE_TYPE_V1), &[pk]) {
            Err(VerifyError::UnknownPredicateFields(e)) => {
                assert!(e.contains("a run/v1 predicate allows only version, "), "{e}");
                assert!(e.contains("fuel and status (a new field"), "{e}");
            }
            other => panic!("{other:?}"),
        }
        // A type error is still reported as before, not as an unknown field.
        let r = RECEIPT.replace("\"fuel\":5", "\"fuel\":-5").replace("\"status\":0}", "\"status\":0,\"x\":1}");
        let e = verify_envelope_checked(&signed(&s, &r, PREDICATE_TYPE_V2), &[pk]).unwrap_err();
        assert!(matches!(&e, VerifyError::Failed(m) if m.contains("predicate.fuel")), "{e:?}");
        // A forged signature is still a signature failure, not a field note.
        let mut env = signed(&s, &RECEIPT.replace("\"status\":0}", "\"status\":0,\"x\":1}"), PREDICATE_TYPE_V2);
        env["signatures"][0]["sig"] = json!(b64().encode([0u8; 64]));
        assert_eq!(verify_envelope_checked(&env, &[pk]).unwrap_err(), VerifyError::Failed("signature does not verify".into()));
    }

    /// A crafted field name is escaped, so it cannot add a line or a
    /// verdict word.
    #[test]
    fn crafted_predicate_field_name_is_escaped() {
        let s = Signer::from_seed([14; 32]);
        let r = RECEIPT.replace("\"status\":0}", "\"status\":0,\"VERIFIED\\nresult     VERIFIED\":1}");
        let e = verify_envelope(&signed(&s, &r, PREDICATE_TYPE_V2), &s.key.verifying_key()).unwrap_err();
        assert!(!e.contains('\n') && !e.contains("VERIFIED"), "{e}");
    }
}
