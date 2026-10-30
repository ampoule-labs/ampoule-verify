# Example receipt (demo only)

A tiny, real Ampoule run receipt you can check with `ampoule-verify`, plus tampered copies that must fail.

**`demo-only.pub` is a demo key made for this example and nothing else. Never trust it for anything real.**

## What was run

`refund.rhai` (refund = 90 + 30) ran once in the Ampoule sandbox: Rhai, QEMU with TCG (no KVM),
deterministic, seed 11, on the kernel with sha256
`60ba914966395b267798704d26a7967dce69b902f10920625e403a856f6d1bf7`. It printed `120` (`output.txt`).
`receipt.json` is the signed DSSE / in-toto envelope (predicate `run/v2`) for that run, signed with the
demo key. It records the sha256 of the payload, output and kernel.

## Files

| file | what |
|---|---|
| `receipt.json` | signed receipt |
| `demo-only.pub` | demo public key (hex Ed25519) |
| `refund.rhai` | the program that ran (payload) |
| `output.txt` | what it printed |
| `tampered/signature.receipt.json` | `receipt.json` with one character of the signature changed |
| `tampered/kernel.receipt.json` | `receipt.json` with the last hex digit of the signed `kernel_sha256` changed |
| `tampered/output.txt` | output changed to `121` |
| `tampered/refund.rhai` | payload changed (shipping 31) |

`SHA256SUMS` lists every file; check with `sha256sum -c SHA256SUMS` inside `examples/`.

## Try it

From the repository root, after building (`target/release/ampoule-verify`):

```sh
V=target/release/ampoule-verify
K=60ba914966395b267798704d26a7967dce69b902f10920625e403a856f6d1bf7
$V examples/receipt.json --key examples/demo-only.pub --payload examples/refund.rhai --output examples/output.txt --expected-kernel-sha256 $K
```

Expected, exit code 0:

```
signature  ok    key cd2fda27e0d3f5e6
run        rhai on qemu, status 0, fuel 10, deterministic seed 11
output     97b912eb4a61df5f  matches
payload    ebd9e5f04fe2788a  matches
kernel     60ba914966395b26  matches --expected-kernel-sha256
checked    signature, output, payload, kernel
result     VERIFIED
```

You do not need the kernel file: `--expected-kernel-sha256` pins it by hash. (If you have the kernel,
`--kernel FILE` gives the same VERIFIED.) Without either, the result is `INCOMPLETE ... kernel not pinned`, exit 5.

## Tampered copies: each must say FAILED, exit code 1

| command (same `$V`, `$K`) | reason line |
|---|---|
| `$V examples/tampered/signature.receipt.json --key examples/demo-only.pub --payload examples/refund.rhai --output examples/output.txt --expected-kernel-sha256 $K` | `signature  FAIL  signature does not verify` |
| `$V examples/tampered/kernel.receipt.json --key examples/demo-only.pub --payload examples/refund.rhai --output examples/output.txt --expected-kernel-sha256 $K` | `signature  FAIL  signature does not verify` |
| `$V examples/receipt.json --key examples/demo-only.pub --payload examples/refund.rhai --output examples/tampered/output.txt --expected-kernel-sha256 $K` | `output     0b05feae0bc84482  DIFFERS` |
| `$V examples/receipt.json --key examples/demo-only.pub --payload examples/tampered/refund.rhai --output examples/output.txt --expected-kernel-sha256 $K` | `payload    80a704b12add7673  DIFFERS` |

Each ends with `result     FAILED`. Exit 1 covers every kind of mismatch; the reason line tells you which.
A wrong pin (for example `--expected-kernel-sha256` with the last digit changed) also fails:
`kernel     60ba914966395b26  DIFFERS from --expected-kernel-sha256 ...`.
