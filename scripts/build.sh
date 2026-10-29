#!/bin/bash
# Reproducibly build ampoule-verify and compare its sha256 with the pin.
# Same sources + rustc 1.99.0 (rust-toolchain.toml) + the same OS image
# (Debian 13, glibc 2.41, gcc 14.2.0, binutils 2.44, x86_64) gives the same
# bytes at any checkout path, under any user, in any target dir.
set -euo pipefail
PIN=3fde4937122d58b360d0e12c04a61263f3f88a120f9041d9079a4b7cc26309bc
ROOT=$(cd "$(dirname "$0")/.." && pwd -P); cd "$ROOT"
# Drop environment overrides that would change the output.
unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_RUSTFLAGS RUSTC CARGO_BUILD_RUSTC \
      RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER CARGO_BUILD_TARGET CARGO_BUILD_TARGET_DIR RUSTC_BOOTSTRAP
for v in $(env | sed -n 's/^\(CARGO_PROFILE_RELEASE_[^=]*\|CARGO_TARGET_[^=]*\)=.*/\1/p'); do unset "$v"; done
export CARGO_INCREMENTAL=0 SOURCE_DATE_EPOCH=0
SYSROOT=$(rustc --print sysroot)
CH=$(cd "${CARGO_HOME:-$HOME/.cargo}" && pwd -P)
OUT=$(mktemp -d "${TMPDIR:-/tmp}/ampoule-verify-build.XXXXXX")
trap 'rm -rf "$OUT"' EXIT
# Path remapping: the checkout is /ampoule, registry sources /cargo, the
# sysroot /rust, the target dir /ampoule/target (the original monorepo layout,
# which the pinned hash was built with).
export CARGO_ENCODED_RUSTFLAGS=$(printf '%s\x1f' \
  "--remap-path-prefix=$ROOT=/ampoule" "--remap-path-prefix=$CH=/cargo" \
  "--remap-path-prefix=$SYSROOT=/rust" "--remap-path-prefix=$OUT=/ampoule/target" | sed 's/\x1f$//')
cargo build --locked --release --target-dir "$OUT" -p attest -p feature-pin \
  --config 'profile.release.opt-level="s"' --config 'profile.release.lto=true' \
  --config 'profile.release.codegen-units=1' --config 'profile.release.debug=true' \
  --config 'profile.release.debug-assertions=false' --config 'profile.release.overflow-checks=false' \
  --config 'profile.release.incremental=false' --config 'profile.release.panic="unwind"' \
  --config 'profile.release.strip="none"' --config 'profile.release.rpath=false' \
  --config 'build.incremental=false'
mkdir -p target/release; cp "$OUT/release/ampoule-verify" target/release/
GOT=$(sha256sum target/release/ampoule-verify | cut -d' ' -f1)
echo "$GOT  target/release/ampoule-verify"
if [ "$GOT" = "$PIN" ]; then echo "MATCH     ampoule-verify $PIN"; else echo "DIFFERENT ampoule-verify (pin $PIN; expected only on another OS image/toolchain)"; exit 1; fi
