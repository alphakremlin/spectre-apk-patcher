# SPECTRE
### Smali Premium & Entitlement Cracker Tool for Reverse Engineering
**by Ramone Scott (@alphakremlin)**

---

## What it does

SPECTRE automatically patches Android APKs to bypass premium/subscription checks. Drop in any APK — it detects which billing SDK the app uses, fetches the right config if needed, patches the relevant smali methods, rebuilds, and signs.

## Features

- **Auto SDK detection** — identifies RevenueCat, Google Billing, Adapty, Qonversion, Apphud, Purchasely, Superwall and more
- **Remote config fetching** — if a config is missing locally it downloads it from GitHub automatically
- **Pattern-based fallback** — scans all smali for `isPremium()`, `isSubscribed()`, `isUnlocked()` etc. even in unknown apps
- **Library-aware** — skips Android/Google/Kotlin standard library code to avoid false positives
- **One command** — decompiles, patches, rebuilds, and signs in a single run

## Requirements

```bash
sudo apt install openjdk-17-jdk apktool apksigner
pip3 install requests --break-system-packages
```

## Usage

```bash
# Patch any APK
python3 patcher.py myapp.apk

# Dry run — see what it finds without writing anything
python3 patcher.py myapp.apk --dry-run

# Only patch the app's own package classes (stricter)
python3 patcher.py myapp.apk --app-only
```

Output: `myapp_patched.apk` — ready to install.

```bash
cp myapp_patched.apk /sdcard/
# Then tap to install on device (enable unknown sources)
```

## Supported SDKs

| SDK | Patched Method |
|-----|---------------|
| RevenueCat | `EntitlementInfo.isActive()` → true |
| Google Play Billing | `Purchase.isAcknowledged()` → true |
| Adapty | `AccessLevel.isActive()` → true |
| Qonversion | `QPermission.isActive()` → true |
| Apphud | `ApphudSubscription.isActive()` → true |
| Purchasely | `PLYSubscription.isActive()` → true |
| Superwall | `RawStoreProduct.isSubscription()` → true |

## Adding configs

Configs live in `configs/<sdk_name>.json`. Format:

```json
{
  "name": "SDK Display Name",
  "detect": ["com/example/sdk/"],
  "patches": [
    {
      "file": "com/example/sdk/Subscription.smali",
      "method": "isActive",
      "returns": "Z",
      "value": true
    }
  ]
}
```

Add new SDKs by dropping a config file here — SPECTRE picks them up automatically. PRs welcome.

## How it works

```
Input APK
   ↓
apktool d → decompile to smali
   ↓
Detect SDKs → match namespace paths against configs/
   ↓
Fetch missing configs from GitHub (auto)
   ↓
Apply targeted patches (exact class + method)
   ↓
Pattern scan → catch isPremium/isSubscribed/etc.
   ↓
apktool b → rebuild APK
   ↓
apksigner → sign with generated keystore
   ↓
output_patched.apk ✅
```

## Disclaimer

For educational and personal use only. Respect app developers and their work.
