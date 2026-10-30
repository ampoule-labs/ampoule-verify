# ampoule-verify

`ampoule-verify` checks a signed Ampoule run receipt (an in-toto statement in a
DSSE envelope, Ed25519) without trusting the host that produced it. Give it the
receipt, the public key(s) you pin, and optionally the output, payload and
kernel files; it re-hashes them and compares them with the signed digests.

The receipt format is specified in [`attest/PREDICATE.md`](attest/PREDICATE.md).
Run `ampoule-verify --help` for usage and exit codes (0 VERIFIED, 1 FAILED,
2 usage error, 3 NOT REPLAYABLE, 4 RUN FAILED, 5 INCOMPLETE).

## Scope and limits

- This repo is the verifier only. The producer (the sealed micro-VM, its
  kernel and runtimes) is not included. A receipt proves which kernel, payload
  and seed produced which output under a key you trust; it does not prove the
  key holder ran it honestly, and it says nothing about whether a grader or
  test is sound.
- The same binary also has `keygen` and `pubkey` helpers for Ed25519 keys.
- Signatures are only checked against keys you pass with `--key`; keys found
  inside a receipt are never trusted.

## Quickstart: verify the demo receipt

    git clone https://github.com/ampoule-labs/ampoule-verify && cd ampoule-verify
    cargo build --release -p attest
    target/release/ampoule-verify examples/receipt.json \
      --key examples/demo-only.pub \
      --payload examples/refund.rhai --output examples/output.txt \
      --expected-kernel-sha256 60ba914966395b267798704d26a7967dce69b902f10920625e403a856f6d1bf7

It ends with `result     VERIFIED` and exit code 0. [`examples/`](examples/README.md)
also has tampered copies that each end with `FAILED` and exit code 1. The demo
key is for this example only; never trust it for anything real.

Needs rustup; the pinned toolchain comes from `rust-toolchain.toml` (some
rustup versions need `rustup toolchain install 1.99.0` first).

## Build

    cargo build --release -p attest      # ordinary build, any platform

An ordinary build works anywhere but does not give the pinned hash below;
only `./scripts/build.sh` on the pinned image (Debian 13) does.

## Reproduce the pinned hash

The published binary is

    3fde4937122d58b360d0e12c04a61263f3f88a120f9041d9079a4b7cc26309bc  ampoule-verify

Requirements: the exact OS image it was built on (Debian 13, glibc 2.41,
gcc 14.2.0, binutils 2.44, x86_64) and rustc 1.99.0 (pinned by
`rust-toolchain.toml`; rustup installs it). The binary links dynamically to
glibc and libgcc_s, so another distro or release gives a different hash.

    git clone https://github.com/ampoule-labs/ampoule-verify && cd ampoule-verify
    ./scripts/build.sh

It builds from scratch in a temporary target dir with `--locked`, the release
profile pinned on the command line, `CARGO_INCREMENTAL=0`, overriding
environment variables cleared, and paths remapped (`checkout -> /ampoule`,
`$CARGO_HOME -> /cargo`, sysroot `-> /rust`, target `-> /ampoule/target`), so
the checkout path, user and target dir don't matter. It prints `MATCH` or
`DIFFERENT` and copies the binary to `target/release/ampoule-verify`.

`feature-pin/` is an empty build-only crate: the pinned binary was first built
in a larger workspace where cargo unified a few dependency features (serde
`derive`, libc and memchr `default`); building `feature-pin` alongside
`attest` restores that feature set. It adds no code and no new crates to the
binary.

## Tests and vectors

    CARGO_TARGET_DIR=target-test cargo test --release -p attest

The separate target dir keeps the tests from overwriting the reproduced
binary in `target/release/ampoule-verify`.

`attest/tests/vectors/` holds conformance vectors: small-order and
non-canonical Ed25519 keys with keyless forgeries (all must be refused) and
saved results with a copied attestation line. Public keys only; no secret key.

## License

Apache-2.0, see [LICENSE](LICENSE) and [NOTICE](NOTICE). Copyright 2026 Igor Pistoliaka.
