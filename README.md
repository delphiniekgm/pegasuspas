# Pegasus Android Detector

A Lazarus / Free Pascal desktop tool that scans an Android device (via ADB) or a
folder of APKs for indicators of Pegasus and other mercenary spyware.

## Detection definitions (MVT)

Indicators are sourced from the
[MVT project](https://github.com/mvt-project/mvt) ecosystem and loaded directly
as STIX 2.1 files from `data/`:

| File | Family | Source |
|------|--------|--------|
| `data/pegasus.stix2` | NSO-Pegasus | Amnesty International, `AmnestyTech/investigations` (`2021-07-18_nso/pegasus.stix2`) |
| `data/android_campaign.stix2` | MVT-Android-Campaign | Amnesty International / Google, `AmnestyTech/investigations` (`2023-03-29_android_campaign/malware.stix2`) |

These are the exact files indexed by MVT's `indicators.yaml`. To refresh the
definitions, replace the `*.stix2` files in `data/` (keep the `.stix2` suffix).
The parser handles domain, IP, URL, email, file-hash and package-name patterns.

You can also add family-based rules as `*.txt` files (see `data/README.md`).

## What it checks

- Package name / SHA-256 / MD5 / signer / permission / string / class IoCs (txt rules).
- STIX2 indicators: known C2 domains (incl. subdomains), IPs, URLs, emails, hashes and package names.
- Optional: SMS messages (bodies) can be scanned for the same C2 domains, URLs, IPs
  and emails (see "Message scanning" below).

## Building

Requires Lazarus (LCL) and Free Pascal 3.2.2. Adjust `LAZ_ROOT` in the
`build_*.bat` files if your install differs.

    build_gui.bat     -> bin\pegasus_scanner.exe  (GUI)
    build_cli.bat     -> bin\pegasus_cli.exe      (console)
    build_test.bat    -> runs tests\selftest.lpr

## Usage

    pegasus_scanner              # GUI
    pegasus_scanner --console    # console mode
    pegasus_cli --help

    pegasus_cli --device SERIAL
    pegasus_cli --demo C:\path\to\apks
    pegasus_cli --all --max 100
    pegasus_cli --device SERIAL --messages
    pegasus_cli --clear

## Message scanning (optional)

Pass `--messages` (CLI) or tick "Download and scan SMS messages" (GUI) to also
pull the device's SMS messages and scan each body for known Pegasus / mercenary
spyware indicators (C2 domains incl. subdomains, URLs, IPs and email addresses).

Extraction uses two methods with automatic fallback:

1. `adb shell content query --uri content://sms` (dependency-free).
2. If that returns nothing, `adb pull` of `mmssms.db` is attempted and parsed by
   a built-in, dependency-free SQLite reader.

All scanned messages (up to `MessagesMaxRows`) are listed in the report, with
matched messages flagged/highlighted and showing the matched indicator and
family.

> **Note:** on most modern, non-rooted devices ADB cannot read SMS
> (`content://sms` is protected and `mmssms.db` lives under `/data/data`, which
> requires root). The feature therefore works mainly on rooted devices and
> emulators, and reports "SMS not accessible" otherwise.

## Notes

- The indicators in `data/` come from the upstream threat-intelligence reports
  referenced above; verify and refresh them before operational use.
- A device scan requires USB debugging enabled and `bin\adb.exe` present.
- Pulled APKs and extracted files are cached in the working directory. Re-scanning
  the same device reuses them (skips re-downloading); scanning a *different* device
  clears the cache automatically first. Use `--clear` (CLI) or the GUI "Clear..."
  button to wipe it manually.
