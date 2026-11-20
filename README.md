# RustChain Bounty #13953 — Adversarial Miner Self-Test (QEMU user-mode arch spoof)

Evidence pack for https://github.com/Scottcjn/rustchain-bounties/issues/13953
Claimant: DSP-AID · RTC wallet: `RTCa628d57063aa8eb9583e2b2b10da9b8be7df332f`

## Technique (not previously shown on that thread)

**CPU-architecture spoofing via QEMU user-mode emulation**: the miner runs in an
`aarch64` Python (`python:3.12-slim-bookworm --platform linux/arm64`) executed by
QEMU TCG (`tonistiigi/binfmt`, `qemu-aarch64`) on an x86_64 Docker host — so
`uname`/`platform.machine()` claim ARM while the real silicon is Intel Xeon.
Prior claims covered hypervisor/container *identity* leaks (Tencent KVM, WSL2,
Docker, K8s, GCE, Termux PRoot, GitHub runner, Netcup, VMware); none spoofed the
architecture itself.

## Code under test

- `Scottcjn/Rustchain` main @ `78176897c4f78f9fde8d8d832df7cf468a863cbc` (2026-11-19):
  `miners/linux/fingerprint_checks.py`, `miners/linux/rustchain_linux_miner.py` (v2.2.1-rip200)
- `clawrtc==1.8.0` (PyPI sdist) bundled `clawrtc/data/fingerprint_checks.py`

## Environment

- Docker host: Ubuntu 24.04 (Linux 6.8.0-149-generic, x86_64), itself a Hyper-V guest
  (`systemd-detect-virt: microsoft`, DMI `Microsoft Corporation / Virtual Machine`)
- Docker 29.9.3; binfmt arm64 via `docker run --rm --privileged tonistiigi/binfmt --install arm64`
- Container: `python:3.12-slim-bookworm` @ linux/arm64, CPython 3.12.16 aarch64

## Rounds (logs in this pack)

| Round | What was tried | Result |
|---|---|---|
| A `roundA_host.txt` | native x86_64 baseline on the Hyper-V host | anti-emulation FAIL, 5 indicators (DMI microsoft ×3, cpuinfo:hypervisor, detect-virt:microsoft) |
| B `roundB_arm64.txt` | real miner `--dry-run --show-payload` against https://rustchain.org inside emulated aarch64 | `[6/6] Anti-Emulation... FAIL`, `Fingerprint pass status: False`, health probe HTTP 200 (node 2.2.1-rip200). Caught via 3 Hyper-V DMI leaks visible through the container |
| C `roundC_masked.txt` | arch spoof + all 7 `/sys/class/dmi/id/*` identity files bind-mounted over with fake bare-metal values, no detect-virt binary in image | check 6 locally **silenced** (0 indicators) — but QEMU's synthetic cpuinfo bet itself: `CPU implementer : 0x00` + `ARMv8 Processor rev 0 (v8l)` (real ARM silicon uses 0x41/0x51/0x61...) |
| C' `roundC1_cachefail_excerpt.txt` | same as C, earlier run | full suite still FAILED via `cache_timing` (`no_cache_hierarchy`) — TCG cannot reliably fake the L1→L2→L3 latency gradient (non-deterministic under host load) |

## Honest findings

1. **Detection confirmed** against the live miner stack in a new environment class
   (CPU-emulated userland): Round B is the clean demonstration the bounty asks for.
2. `check_anti_emulation` alone can be **locally silenced** inside a container by
   bind-mounting fake DMI files (Round C). Not claimed as a *bypass*: acceptance by a
   deployed node goes through attestation, which was deliberately not exercised here
   (no attest/enroll/mine; dry-run only, read-only RPC discipline). If pursued to a
   proven deployed-node bypass it belongs in the SECURITY.md advisory track.
3. QEMU user-mode fabricates `/proc/cpuinfo` with `CPU implementer 0x00`; cross-checking
   that vendor code against `platform.machine()` (or a CPUID probe) would make check 6
   robust against this exact spoof even when DMI is masked. Hardening suggestion, not a
   security claim.
4. The behavioral layer caught the emulator when check 6 was blinded in one run
   (`cache_timing` FAIL); on a re-run it passed at l2_l1=1.078 — timing checks are the
   noisy-but-real second line of defense under TCG.

## Reproduce

```bash
# on any x86_64 Docker host
docker run --rm --privileged tonistiigi/binfmt --install arm64
docker pull --platform linux/arm64 python:3.12-slim-bookworm
cd pack/            # this directory
bash run_all.sh host         # Round A (needs python3 on host)
bash run_all.sh arm64        # Round B (miner dry-run + self-test, emulated aarch64)
bash run_all.sh masked       # Round C / C' (self-test clean-expectation + detailed JSON)
```

`bounty_selftest.py <detected|clean>` is the assert-based unit test: it runs both the
repo-main and clawrtc-1.8.0 anti-emulation checks, prints full indicator JSON, cross-
checks the claimed architecture (`ARCH_MISMATCH` / `QEMU_SYNTHETIC_CPUINFO` lines),
runs all 6 checks, and exits non-zero if the verdict doesn't match reality.

## Files

- `bounty_selftest.py` — self-test harness (asserts detection verdict)
- `run_all.sh` — round orchestrator (host / arm64 / masked)
- `fingerprint_checks.py`, `rustchain_linux_miner.py` — verbatim from Rustchain main @ 7817689
- `clawrtc_fingerprint_checks.py` — verbatim from clawrtc-1.8.0 sdist (`clawrtc/data/`)
- `fakes/dmi_*` — fake bare-metal DMI identity files used for the Round C masks
- `roundA_host.txt`, `roundB_arm64.txt`, `roundC_masked.txt`, `roundC1_cachefail_excerpt.txt` — captured outputs
