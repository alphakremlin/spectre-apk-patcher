#!/usr/bin/env python3
"""
SPECTRE — Smali Premium & Entitlement Cracker Tool for Reverse Engineering
by Ramone Scott (@alphakremlin)

Usage:
  python3 patcher.py <input.apk>
  python3 patcher.py <input.apk> --dry-run
  python3 patcher.py <input.apk> --app-only
"""

import sys
import os
import re
import json
import subprocess
import argparse
import zipfile
import shutil
from pathlib import Path

# ── ANSI colours ──────────────────────────────────────────────────────────────
R  = "\033[91m"   # red
G  = "\033[92m"   # green
Y  = "\033[93m"   # yellow
C  = "\033[96m"   # cyan
W  = "\033[97m"   # white
DM = "\033[2m"    # dim
X  = "\033[0m"    # reset

_L1 = r" ___________ ______ _____ ___________ _____ "
_L2 = r"/  ___| ___ \  ___/  __ \_   _| ___ \  ___|"
_L3 = r"\ `--.| |_/ / |__ | /  \/ | | | |_/ / |__  "
_L4 = r" `--. \  __/|  __|| |     | | |    /|  __| "
_L5 = r"/\__/ / |   | |___| \__/\ | | | |\ \| |___ "
_L6 = r"\____/\_|   \____/ \____/ \_/ \_| \_\____/ "

BANNER = (
    f"\n{R}{_L1}{X}\n"
    f"{R}{_L2}{X}\n"
    f"{R}{_L3}{X}\n"
    f"{Y}{_L4}{X}\n"
    f"{Y}{_L5}{X}\n"
    f"{Y}{_L6}{X}\n"
    f"\n{W}  Smali Premium & Entitlement Cracker Tool{X}\n"
    f"{W}        for Reverse Engineering{X}\n"
    f"{DM}  ─────────────────────────────────────────{X}\n"
    f"{C}  by Ramone Scott  {DM}(@alphakremlin){X}\n"
    f"{DM}  ─────────────────────────────────────────{X}\n"
)

def print_banner():
    print(BANNER)

try:
    import requests
except ImportError:
    subprocess.run([sys.executable, "-m", "pip", "install",
                    "requests", "--break-system-packages", "-q"])
    import requests

# ── Remote config registry ────────────────────────────────────────────────────
# When a config is not found locally it is fetched from here.

REMOTE_BASE = (
    "https://raw.githubusercontent.com/alphakremlin/"
    "apk-patcher/main/configs"
)

KNOWN_SDKS = [
    "revenuecat", "google_billing", "adapty",
    "qonversion", "apphud", "purchasely", "superwall",
]

# ── Library namespaces to skip in pattern scan ────────────────────────────────

SKIP_PREFIXES = (
    "android/", "androidx/", "com/google/", "com/android/",
    "kotlin/", "kotlinx/",
    "io/reactivex/", "rx/",
    "io/sentry/", "com/sentry/",
    "okhttp3/", "okio/",
    "org/apache/", "org/json/", "org/slf4j/",
    "com/squareup/", "com/jakewharton/",
    "javax/", "java/",
    "brut/", "org/smali/",
)

# ── Pattern-based premium method names ───────────────────────────────────────

TRUE_RE = re.compile(
    r'^(is|has|can)(Premium|Pro|Vip|Paid|Subscribed|Subscriber|Licensed|'
    r'Purchased|Unlocked|Activated|Full|Elite|Plus|Gold|Member|Entitled|'
    r'Registered|Verified|Donate|Donor|Enabled|Allowed)$',
    re.IGNORECASE
)
FALSE_RE = re.compile(
    r'^(is|has)(Trial|Demo|Limited|Restricted|Locked|TrialExpired|FreeUser)$',
    re.IGNORECASE
)

# ── Config loader ─────────────────────────────────────────────────────────────

CONFIG_DIR = Path(__file__).parent / "configs"

def load_config(name: str) -> dict | None:
    """Load a config file locally, or fetch it from GitHub if missing."""
    local = CONFIG_DIR / f"{name}.json"

    if local.exists():
        with open(local) as f:
            return json.load(f)

    # Try to fetch from remote
    url = f"{REMOTE_BASE}/{name}.json"
    print(f"   🌐 Config '{name}' not found locally — fetching from GitHub...")
    try:
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            local.write_text(r.text)
            print(f"   ✅ Downloaded and saved: configs/{name}.json")
            return r.json()
        else:
            print(f"   ⚠️  Not found on GitHub either (HTTP {r.status_code})")
    except Exception as e:
        print(f"   ⚠️  Could not fetch config: {e}")
    return None

def list_remote_configs() -> list[str]:
    """Fetch the list of all available configs from GitHub."""
    try:
        url = f"{REMOTE_BASE}/index.json"
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            return r.json().get("sdks", KNOWN_SDKS)
    except Exception:
        pass
    return KNOWN_SDKS

# ── SDK detection ─────────────────────────────────────────────────────────────

def detect_sdks(work: Path) -> list[dict]:
    """
    Walk the decompiled smali dirs, collect all namespace paths,
    then match against every known SDK config's detect list.
    """
    # Collect unique top-level paths (fast)
    paths = set()
    for smali_dir in work.glob("smali*"):
        for p in smali_dir.rglob("*.smali"):
            rel = str(p.relative_to(smali_dir)).replace("\\", "/")
            paths.add(rel)

    detected = []
    all_sdks = list_remote_configs()

    for sdk_name in all_sdks:
        cfg = load_config(sdk_name)
        if not cfg:
            continue
        for detect_path in cfg.get("detect", []):
            if any(detect_path in p for p in paths):
                detected.append(cfg)
                print(f"   📡 Detected SDK: {cfg['name']}")
                break

    return detected

# ── Smali patching ────────────────────────────────────────────────────────────

_inject_counter = 0  # global label uniquifier

def make_bool_method(sig: str, value: bool) -> str:
    val = "0x1" if value else "0x0"
    return (
        f"{sig}\n"
        "    .locals 1\n\n"
        f"    const/4 v0, {val}\n\n"
        "    return v0\n\n"
        ".end method\n"
    )

def apply_json_date_inject(work: Path, cfg: dict, patch: dict, dry_run: bool) -> list[str]:
    """
    Patch a JSONObject-returning method to inject future expire dates before
    every return statement.

    Targets apps where native code (e.g. Qt/GNUstep ObjC bridge) reads raw
    RevenueCat JSON directly instead of calling Java getters like isActive().
    Classic symptom: isActive() patch has no effect — subscription still locked.

    Strategy:
      1. Find the target method by name + return type.
      2. Bump .locals by 2 for two scratch string registers.
      3. Before every return-object, inject a try/catch block that calls
         JSONObject.put() to overwrite each date key with a far-future value.
    """
    global _inject_counter

    rel_file    = patch["file"]
    method_name = patch["method"]
    return_type = patch.get("returns", "Lorg/json/JSONObject;")
    keys        = patch.get("keys", ["expires_date", "grace_period_expires_date"])
    future_date = patch.get("date", "2099-12-31T23:59:59Z")

    results = []

    method_pat = re.compile(
        rf'(\.method[^\n]*\b{re.escape(method_name)}\(\){re.escape(return_type)}\n)'
        rf'(.*?)'
        rf'(\.end method)',
        re.DOTALL
    )
    return_pat = re.compile(r'([ \t]*)(return-object[ \t]+(v\d+|p\d+))', re.MULTILINE)

    for smali_dir in work.glob("smali*"):
        target = smali_dir / rel_file
        if not target.exists():
            continue

        text  = target.read_text(encoding="utf-8", errors="replace")
        found = [0]

        def patch_method(m, found=found):
            global _inject_counter
            sig  = m.group(1)
            body = m.group(2)
            end  = m.group(3)

            if dry_run:
                if return_pat.search(body):
                    found[0] += 1
                return m.group(0)

            # Allocate 2 extra locals for key + value strings
            loc_m = re.search(r'(\.locals\s+)(\d+)', body)
            if loc_m:
                n        = int(loc_m.group(2))
                key_reg  = f'v{n}'
                val_reg  = f'v{n + 1}'
                body     = body.replace(loc_m.group(0), f'.locals {n + 2}', 1)
            else:
                # Can't safely inject without knowing register count — skip
                print(f"   ⚠️  No .locals in {method_name}() — skipping date inject")
                return m.group(0)

            def inject_before_return(rm):
                global _inject_counter
                _inject_counter += 1
                lbl      = f'spectre_dates_{_inject_counter}'
                indent   = rm.group(1)
                ret_stmt = rm.group(2)
                ret_reg  = rm.group(3)

                lines = [f'{indent}:try_start_{lbl}']
                lines.append(f'{indent}const-string {val_reg}, "{future_date}"')
                for key in keys:
                    lines.append(f'{indent}const-string {key_reg}, "{key}"')
                    lines.append(
                        f'{indent}invoke-virtual {{{ret_reg}, {key_reg}, {val_reg}}}, '
                        f'Lorg/json/JSONObject;->put('
                        f'Ljava/lang/String;Ljava/lang/String;)Lorg/json/JSONObject;'
                    )
                lines.append(f'{indent}:try_end_{lbl}')
                lines.append(
                    f'{indent}.catch Lorg/json/JSONException; '
                    f'{{:try_start_{lbl} .. :try_end_{lbl}}} :catch_{lbl}'
                )
                lines.append(f'{indent}:catch_{lbl}')
                lines.append(f'{indent}{ret_stmt}')
                found[0] += 1
                return '\n'.join(lines)

            body = return_pat.sub(inject_before_return, body)
            return sig + body + end

        new_text = method_pat.sub(patch_method, text)

        if found[0]:
            results.append(
                f"  🗓️  [{cfg['name']}] {target.name}::{method_name}() "
                f"→ injected future dates ({', '.join(keys)})"
            )
            if not dry_run:
                target.write_text(new_text, encoding="utf-8")

    return results


def apply_sdk_patches(work: Path, sdks: list[dict], dry_run: bool) -> list[str]:
    """Apply targeted patches from SDK config files."""
    patches = []
    for cfg in sdks:
        for patch in cfg.get("patches", []):
            patch_type = patch.get("type", "bool")

            if patch_type == "json_date_inject":
                patches.extend(apply_json_date_inject(work, cfg, patch, dry_run))
                continue

            # ── Boolean return patch (default) ────────────────────────────────
            rel_file  = patch["file"]
            method    = patch["method"]
            ret_type  = patch.get("returns", "Z")
            value     = patch["value"]

            if ret_type != "Z":
                continue  # only boolean patches handled here

            for smali_dir in work.glob("smali*"):
                target = smali_dir / rel_file
                if not target.exists():
                    continue

                text = target.read_text(encoding="utf-8", errors="replace")
                pattern = re.compile(
                    rf'(\.method[^\n]*\b{re.escape(method)}\(\)Z\n)(.*?)(\.end method)',
                    re.DOTALL
                )

                found = [0]
                def replacer(m, sig=None, v=value, n=method, f=target.name, c=found):
                    sig = m.group(1).rstrip('\n')
                    c[0] += 1
                    label = "true" if v else "false"
                    patches.append(
                        f"  🎯 [{cfg['name']}] {f}::{n}() → {label}"
                    )
                    return make_bool_method(sig, v) if not dry_run else m.group(0)

                new_text = pattern.sub(replacer, text)
                if found[0] and not dry_run:
                    target.write_text(new_text, encoding="utf-8")

    return patches

def patch_smali_file(filepath: Path, dry_run: bool,
                     app_only: bool, app_pkg: str) -> list[str]:
    """Pattern-based scan on a single smali file."""
    rel = str(filepath).replace("\\", "/")
    for prefix in SKIP_PREFIXES:
        if prefix in rel:
            return []
    if app_only and app_pkg and app_pkg.replace(".", "/") not in rel:
        return []

    text = filepath.read_text(encoding="utf-8", errors="replace")
    patches = []
    method_pat = re.compile(
        r'(\.method\s+[^\n]+\n)(.*?)(\.end method)', re.DOTALL
    )

    def replace_method(m):
        sig = m.group(1).rstrip('\n')
        if not sig.rstrip().endswith(')Z'):
            return m.group(0)
        name_m = re.search(r'(\w+)\(\)', sig)
        if not name_m:
            return m.group(0)
        name = name_m.group(1)

        if TRUE_RE.match(name):
            patches.append(f"  ✅ {filepath.name}::{name}() → true")
            return make_bool_method(sig, True) if not dry_run else m.group(0)
        elif FALSE_RE.match(name):
            patches.append(f"  🔒 {filepath.name}::{name}() → false")
            return make_bool_method(sig, False) if not dry_run else m.group(0)
        return m.group(0)

    new_text = method_pat.sub(replace_method, text)
    if patches and not dry_run:
        filepath.write_text(new_text, encoding="utf-8")
    return patches

# ── APK tools ─────────────────────────────────────────────────────────────────

def run(cmd: list, label: str) -> bool:
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"❌ {label} failed:\n{result.stderr[-800:]}")
        return False
    return True

def get_package_name(apk: Path) -> str:
    r = subprocess.run(["aapt", "dump", "badging", str(apk)],
                       capture_output=True, text=True)
    m = re.search(r"package: name='([^']+)'", r.stdout)
    return m.group(1) if m else ""

def decompile(apk: Path, out: Path) -> bool:
    if out.exists():
        shutil.rmtree(out)
    print(f"\n📦 Decompiling {apk.name} ...")
    ok = run(["apktool", "d", "-f", "-r", str(apk), "-o", str(out)], "apktool d")
    if ok: print(f"   → {out}/")
    return ok

def build(out: Path, unsigned: Path) -> bool:
    print("\n🔨 Rebuilding APK ...")
    ok = run(["apktool", "b", str(out), "-r", "-o", str(unsigned)], "apktool b")
    if ok: print(f"   → {unsigned}")
    return ok

def sign(unsigned: Path, signed: Path) -> bool:
    keystore = Path("patch.keystore")
    if not keystore.exists():
        print("🔑 Generating keystore ...")
        run([
            "keytool", "-genkey", "-noprompt",
            "-keystore", str(keystore),
            "-alias", "patch", "-keyalg", "RSA", "-keysize", "2048",
            "-validity", "10000",
            "-dname", "CN=Patch, OU=Patch, O=Patch, L=NA, S=NA, C=US",
            "-storepass", "patch123", "-keypass", "patch123",
        ], "keytool")
    print("✍️  Signing APK ...")
    ok = run([
        "apksigner", "sign",
        "--ks", str(keystore), "--ks-pass", "pass:patch123",
        "--out", str(signed), str(unsigned),
    ], "apksigner")
    if ok: print(f"   → {signed}")
    return ok

# ── XAPK handling ─────────────────────────────────────────────────────────────

def extract_base_from_xapk(xapk: Path, out_dir: Path) -> tuple[Path, str]:
    """
    Extract the base APK from an XAPK.
    Returns (base_apk_path, base_entry_name).
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(xapk) as z:
        entries = z.namelist()
        # Base APK is the one named after the package or just 'base.apk'
        base_entry = next(
            (e for e in entries if e.endswith(".apk") and
             not e.startswith("config.")), None
        )
        if not base_entry:
            raise RuntimeError("No base APK found inside XAPK")
        dest = out_dir / "base.apk"
        with z.open(base_entry) as src, open(dest, "wb") as dst:
            dst.write(src.read())
        print(f"   Extracted base: {base_entry} → {dest}")
        return dest, base_entry

def strip_and_resign_apk(raw: Path, keystore: Path, ks_pass: str) -> Path:
    """
    Strip existing signature, re-store .so files uncompressed (required by
    Android for native lib extraction), zipalign, then re-sign.
    """
    stripped = raw.with_suffix(".stripped.apk")
    aligned  = raw.with_suffix(".aligned.apk")
    signed   = raw.with_suffix(".signed.apk")

    # Re-package: .so files must be ZIP_STORED (uncompressed) for Android
    with zipfile.ZipFile(raw) as src, \
         zipfile.ZipFile(stripped, "w") as dst:
        for item in src.namelist():
            if item.startswith("META-INF/"):
                continue
            data = src.read(item)
            if item.endswith(".so") or item == "resources.arsc":
                # .so  → must be ZIP_STORED for mmap (native lib extraction)
                # .arsc → must be ZIP_STORED + 4-byte aligned on API 30+
                info = src.getinfo(item)
                info.compress_type = zipfile.ZIP_STORED
                dst.writestr(info, data)
            else:
                dst.writestr(item, data, compress_type=zipfile.ZIP_DEFLATED)

    # zipalign -p 4 (page-align .so files to 4096 bytes for mmap)
    result = subprocess.run(
        ["zipalign", "-p", "-f", "4", str(stripped), str(aligned)],
        capture_output=True, text=True
    )
    stripped.unlink(missing_ok=True)
    if result.returncode != 0:
        raise RuntimeError(f"zipalign failed: {result.stderr[:300]}")

    # Sign
    result = subprocess.run([
        "apksigner", "sign",
        "--ks", str(keystore), "--ks-pass", f"pass:{ks_pass}",
        "--out", str(signed), str(aligned),
    ], capture_output=True, text=True)

    aligned.unlink(missing_ok=True)
    if result.returncode != 0:
        raise RuntimeError(f"apksigner failed: {result.stderr[:300]}")
    return signed

def rebuild_xapk(original_xapk: Path, patched_base: Path,
                 base_entry_name: str, out_xapk: Path,
                 keystore: Path, ks_pass: str):
    """
    Rebuild XAPK with patched base APK.
    Re-signs ALL splits with the same keystore so signatures are consistent.
    (Mismatched signatures cause INSTALL_FAILED_INVALID_APK on SAI.)
    """
    print(f"\n📦 Rebuilding XAPK — re-signing all splits ...")
    tmp = out_xapk.parent / f"_resign_tmp_{out_xapk.stem}"
    tmp.mkdir(exist_ok=True)

    try:
        with zipfile.ZipFile(out_xapk, "w", compression=zipfile.ZIP_DEFLATED) as zout:
            with zipfile.ZipFile(original_xapk) as zin:
                for entry in zin.namelist():
                    if not entry.endswith(".apk"):
                        zout.writestr(entry, zin.read(entry))
                        continue

                    raw = tmp / entry.replace("/", "_")
                    if entry == base_entry_name:
                        # Use the already-patched+signed base
                        shutil.copy2(patched_base, raw)
                    else:
                        raw.write_bytes(zin.read(entry))

                    try:
                        resigned = strip_and_resign_apk(raw, keystore, ks_pass)
                        zout.write(resigned, entry)
                        print(f"   ✅ {entry}")
                        resigned.unlink(missing_ok=True)
                    except RuntimeError as e:
                        print(f"   ⚠️  {entry} — {e} (using original)")
                        zout.write(raw, entry)
                    raw.unlink(missing_ok=True)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    size = out_xapk.stat().st_size / 1e6
    print(f"   → {out_xapk} ({size:.1f} MB)")

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="SPECTRE — APK Premium Patcher")
    parser.add_argument("apk", help="Path to input .apk or .xapk")
    parser.add_argument("--dry-run", action="store_true",
                        help="Scan only — no writes")
    parser.add_argument("--app-only", action="store_true",
                        help="Pattern scan only the app's own package")
    args = parser.parse_args()

    input_path = Path(args.apk).resolve()
    if not input_path.exists():
        print(f"❌ File not found: {input_path}"); sys.exit(1)

    # ── XAPK: extract base APK first ──────────────────────────────────────────
    is_xapk = input_path.suffix.lower() == ".xapk"
    xapk_base_entry = None

    if is_xapk:
        print(f"\n📂 XAPK detected — extracting base APK ...")
        xapk_tmp = Path(f"xapk_tmp_{input_path.stem}")
        apk, xapk_base_entry = extract_base_from_xapk(input_path, xapk_tmp)
    else:
        apk = input_path

    stem     = input_path.stem
    work     = Path(f"work_{stem}")
    unsigned = Path(f"{stem}_unsigned.apk")
    signed   = Path(f"{stem}_patched.apk")
    out_xapk = Path(f"{stem}_patched.xapk")

    pkg = get_package_name(apk)
    if pkg: print(f"📱 Package: {pkg}")

    # 1. Decompile
    if not decompile(apk, work):
        sys.exit(1)

    all_patches = []

    # 2. Detect SDKs + apply targeted patches
    print("\n🔎 Detecting subscription SDKs ...")
    sdks = detect_sdks(work)
    if not sdks:
        print("   None detected — will rely on pattern scan.")
    else:
        sdk_patches = apply_sdk_patches(work, sdks, args.dry_run)
        if sdk_patches:
            print(f"\n   Applied {len(sdk_patches)} SDK patch(es):")
            for p in sdk_patches: print(p)
        all_patches.extend(sdk_patches)

    # 3. Pattern-based scan
    print("\n🔍 Pattern scanning smali ...")
    for smali_dir in work.glob("smali*"):
        for smali_file in smali_dir.rglob("*.smali"):
            patches = patch_smali_file(
                smali_file, args.dry_run, args.app_only, pkg
            )
            all_patches.extend(patches)

    pattern_only = [p for p in all_patches if "🎯" not in p]
    if pattern_only:
        print(f"   Found {len(pattern_only)} pattern patch(es):")
        for p in pattern_only: print(p)
    elif not sdks:
        print("   ⚠️  No matching methods found.")

    if args.dry_run:
        print(f"\n[dry-run] {len(all_patches)} total patch(es). No files written.")
        sys.exit(0)

    if not all_patches:
        print("\n⚠️  Nothing to patch."); sys.exit(0)

    # 4. Build + sign patched base APK
    if not build(work, unsigned): sys.exit(1)
    if not sign(unsigned, signed): sys.exit(1)
    unsigned.unlink(missing_ok=True)

    # 5. If XAPK — inject patched base back, output .xapk for SAI
    if is_xapk:
        rebuild_xapk(input_path, signed, xapk_base_entry, out_xapk,
                     Path("patch.keystore"), "patch123")
        signed.unlink(missing_ok=True)
        shutil.rmtree(xapk_tmp, ignore_errors=True)
        size = out_xapk.stat().st_size / 1e6
        print(f"\n{G}✅ Done → {out_xapk}  ({size:.1f} MB){X}")
        print(f"\n{Y}⚠️  This is a split APK — install with SAI:{X}")
        print(f"   1. Install SAI (Split APKs Installer) from Play Store")
        print(f"   2. cp {out_xapk} /sdcard/")
        print(f"   3. Open SAI → Install APKs → select {out_xapk.name}")
    else:
        size = signed.stat().st_size / 1e6
        print(f"\n{G}✅ Done → {signed}  ({size:.1f} MB){X}")
        print(f"   cp {signed} /sdcard/ && tap to install")

if __name__ == "__main__":
    main()
