#!/usr/bin/env python3
"""RustChain Bounty #13953 — adversarial miner self-test.

Runs the real fingerprint suite (repo `fingerprint_checks.py` main branch +
bundled `clawrtc==1.8.0` copy) in the current environment, prints the exact
detection evidence, cross-checks the claimed architecture against
/proc/cpuinfo, and finishes with a machine-checked self-test verdict:

    python3 bounty_selftest.py detected   # expect anti-emulation to FAIL (VM/emulation caught)
    python3 bounty_selftest.py clean      # expect anti-emulation to PASS (masks worked)

Exit code 0 = self-test verdict matched reality, 1 = mismatch.
"""
import importlib.util
import json
import os
import platform
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def read(path):
    try:
        with open(path, "r") as f:
            return f.read().strip()
    except OSError:
        return None


def env_probe():
    cpuinfo = read("/proc/cpuinfo") or ""
    low = cpuinfo.lower()
    dmi = {p.rsplit("/", 1)[-1]: read(p) for p in [
        "/sys/class/dmi/id/product_name", "/sys/class/dmi/id/sys_vendor",
        "/sys/class/dmi/id/board_vendor", "/sys/class/dmi/id/board_name",
        "/sys/class/dmi/id/bios_vendor", "/sys/class/dmi/id/chassis_vendor",
        "/sys/class/dmi/id/chassis_asset_tag"]}
    try:
        virt = subprocess.run(["systemd-detect-virt"], capture_output=True,
                              text=True, timeout=5).stdout.strip() or "none"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        virt = "binary-absent"
    return {
        "machine": platform.machine(),
        "python": platform.python_version(),
        "cpuinfo_vendor": next((l for l in cpuinfo.splitlines()
                                if "vendor_id" in l or "CPU implementer" in l), None),
        "cpuinfo_model": next((l for l in cpuinfo.splitlines()
                               if "model name" in l.lower() or "Hardware" in l), None),
        "cpuinfo_has_hypervisor_flag": "hypervisor" in low,
        "dmi": dmi,
        "systemd_detect_virt": virt,
        "container_env": {k: v for k, v in os.environ.items()
                          if k.lower() in ("container", "docker", "virtual")},
    }


def arch_crosscheck(probe):
    """uname-side arch label vs what /proc/cpuinfo actually reports."""
    raw = read("/proc/cpuinfo") or ""
    claimed = probe["machine"].lower()
    cpuinfo = raw.lower()
    real_x86 = ("genuineintel" in cpuinfo or "authenticamd" in cpuinfo
                or "flags" in cpuinfo and "avx" in cpuinfo)
    claimed_arm = "arm" in claimed or "aarch64" in claimed
    if claimed_arm and real_x86:
        return ("ARCH_MISMATCH: uname says %s but /proc/cpuinfo shows x86_64 "
                "vendor/flags -> QEMU user-mode emulation leak" % probe["machine"])
    if (not claimed_arm) and "CPU implementer" in raw:
        return "ARCH_MISMATCH: uname says %s but cpuinfo is ARM-format" % probe["machine"]
    # QEMU user-mode fakes a synthetic ARM cpuinfo for aarch64 targets; its
    # CPU implementer is 0x00, which no real ARM silicon uses (ARM=0x41,
    # Qualcomm=0x51, Apple=0x61, ...). A real aarch64 box never reports this.
    if claimed_arm and "cpu implementer\t: 0x00" in cpuinfo:
        return ("QEMU_SYNTHETIC_CPUINFO: uname says %s and cpuinfo is ARM-styled, "
                "but CPU implementer 0x00 / 'ARMv8 Processor rev 0 (v8l)' is the "
                "TCG fake-CPU signature, not real silicon" % probe["machine"])
    return None


def main():
    expect = sys.argv[1] if len(sys.argv) > 1 else "detected"
    print("== ENV PROBE ==")
    probe = env_probe()
    print(json.dumps(probe, indent=2))

    mismatch = arch_crosscheck(probe)
    if mismatch:
        print("\n!! " + mismatch)

    repo_mod = load_module("fc_repo", os.path.join(HERE, "fingerprint_checks.py"))
    claw_mod = load_module("fc_clawrtc", os.path.join(HERE, "clawrtc_fingerprint_checks.py"))

    print("\n== ANTI-EMULATION: repo fingerprint_checks.py (Rustchain main) ==")
    repo_pass, repo_data = repo_mod.check_anti_emulation()
    print(json.dumps(repo_data, indent=2))

    print("\n== ANTI-EMULATION: clawrtc==1.8.0 bundled check ==")
    claw_pass, claw_data = claw_mod.check_anti_emulation()
    print(json.dumps(claw_data, indent=2))

    print("\n== FULL SUITE: validate_all_checks() (repo main) ==")
    overall, results = repo_mod.validate_all_checks()

    # --- machine-checked self-test verdict (unit test for this run) ---
    ok = True
    reasons = []
    if expect == "detected":
        if repo_pass:
            ok = False; reasons.append("expected anti_emulation FAIL, got PASS")
        if claw_pass != repo_pass:
            ok = False; reasons.append("repo vs clawrtc disagree: %s vs %s" % (repo_pass, claw_pass))
    elif expect == "clean":
        if not repo_pass:
            ok = False; reasons.append("expected anti_emulation PASS, got FAIL %s" % repo_data)
    else:
        ok = False; reasons.append("unknown expectation %r" % expect)
    print("\nSELFTEST(expect=%s): %s%s" % (
        expect, "PASS" if ok else "FAIL",
        "" if ok else " -> " + "; ".join(reasons)))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
