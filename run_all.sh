#!/usr/bin/env bash
# RustChain Bounty #13953 — adversarial fingerprint self-test rounds.
# Usage: bash run_all.sh host|arm64|masked|maskedcpuinfo
set -u
IMG="python:3.12-slim-bookworm"
DMI_FILES="product_name sys_vendor board_vendor board_name bios_vendor chassis_vendor chassis_asset_tag"

mask_args() {
  local extra=""
  for f in $DMI_FILES; do
    extra="$extra -v $PWD/fakes/dmi_$f:/sys/class/dmi/id/$f:ro"
  done
  echo "$extra"
}

case "${1:?round required}" in
  host)
    python3 bounty_selftest.py detected
    ;;
  arm64)
    # Round B: real miner dry-run + self-test inside aarch64 userland emulated
    # by QEMU user-mode (binfmt) on the x86_64 host — architecture spoof attempt.
    docker run --rm --platform linux/arm64 -v "$PWD":/w -w /w "$IMG" sh -c \
      "pip install --no-cache-dir -q requests clawrtc==1.8.0 \
       && echo '### rustchain_linux_miner.py --dry-run (emulated aarch64) ###' \
       && python3 /w/rustchain_linux_miner.py --dry-run --show-payload; \
       echo; echo '### bounty_selftest.py (emulated aarch64) ###'; \
       python3 /w/bounty_selftest.py detected"
    ;;
  masked)
    # Round C/D: arch spoof + all 7 DMI identity files bind-mounted over with
    # fake bare-metal values; no systemd-detect-virt binary in the image.
    # Honest expectation here is `clean` for check 6 (masks silence it) — the
    # full suite must still FAIL on behavioral checks if QEMU is really caught.
    docker run --rm --platform linux/arm64 $(mask_args) -v "$PWD":/w -w /w "$IMG" sh -c \
      "python3 /w/bounty_selftest.py clean; \
       echo; echo '### fingerprint_checks.py detailed JSON (masked, emulated aarch64) ###'; \
       python3 /w/fingerprint_checks.py"
    ;;
esac
