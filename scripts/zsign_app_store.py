#!/usr/bin/env python3
"""
App Store oriented zsign wrapper.

Default paths are tailored for:
  - zsign: /Users/shayetet/Working/github/zsign/bin/zsign
  - certs: /Users/shayetet/Desktop/working/cer/app-store
  - p12: /Users/shayetet/Desktop/working/cer/app-store/123.p12
  - provision: /Users/shayetet/Desktop/working/cer/app-store/1.mobileprovision
  - p12 password: 123
  - bundle id: comhi.Kingdom.ForceJigsawPuzzle13
"""

from __future__ import annotations

import argparse
import os
import plistlib
import shlex
import shutil
import subprocess
import sys
from pathlib import Path


DEFAULT_ZSIGN = Path("/Users/shayetet/Working/github/zsign/bin/zsign")
DEFAULT_CERT_DIR = Path("/Users/shayetet/Desktop/working/cer/app-store")
DEFAULT_BUNDLE_ID = "comhi.Kingdom.ForceJigsawPuzzle13"
DEFAULT_P12_FILE = Path("/Users/shayetet/Desktop/working/cer/app-store/123.p12")
DEFAULT_PROVISION_FILE = Path("/Users/shayetet/Desktop/working/cer/app-store/1.mobileprovision")
DEFAULT_ENTITLEMENTS_FILE = Path(
    "/Users/shayetet/Desktop/working/cer/app-store/entitlements/entitlements.plist"
)
DEFAULT_P12_PASSWORD = "123"


def find_single_file(directory: Path, pattern: str, explicit_path: str | None) -> Path:
    if explicit_path:
        path = Path(explicit_path).expanduser().resolve()
        if not path.is_file():
            raise FileNotFoundError(f"File not found: {path}")
        return path

    matches = sorted(directory.glob(pattern))
    if not matches:
        raise FileNotFoundError(f"No file matching '{pattern}' in {directory}")
    if len(matches) > 1:
        names = ", ".join(str(p.name) for p in matches)
        raise RuntimeError(
            f"Found multiple files for '{pattern}' in {directory}: {names}. "
            "Please specify explicit path via CLI argument."
        )
    return matches[0].resolve()


def resolve_entitlements(path: str) -> Path:
    entitlements = Path(path).expanduser().resolve()
    if not entitlements.is_file():
        raise FileNotFoundError(f"Entitlements not found: {entitlements}")
    return entitlements


def extract_entitlements_plist_from_signature(app_binary: Path) -> str:
    """Read the embedded XML entitlements slot (same source altool uses when DER matches)."""
    data = app_binary.read_bytes()
    magic = bytes.fromhex("fade7171")
    offset = data.find(magic)
    if offset < 0:
        raise RuntimeError("Entitlements slot not found in signed binary")
    length = int.from_bytes(data[offset + 4 : offset + 8], "big")
    return data[offset + 8 : offset + length].decode("utf-8", "replace")


def verify_signed_entitlements(app_binary: Path) -> None:
    """Fail fast if the main binary still carries disallowed/original entitlements."""
    plist_text = extract_entitlements_plist_from_signature(app_binary)
    blocked = (
        "com.apple.developer.networking.networkextension",
        "hotspot-provider",
    )
    for marker in blocked:
        if marker in plist_text:
            raise RuntimeError(
                f"Signed entitlements still contain '{marker}'. "
                "Ensure -e points to your App Store entitlements.plist and use --force."
            )


def zsign_supports_cert_check(zsign_bin: Path) -> bool:
    """当前 zsign 是否支持 -C 证书预检（旧版发布包无此选项）。"""
    proc = subprocess.run(
        [str(zsign_bin), "-h"],
        capture_output=True,
        text=True,
    )
    text = (proc.stdout or "") + (proc.stderr or "")
    return "-C" in text or "--check" in text


def build_output_path(input_ipa: Path, output_ipa: str | None) -> Path:
    if output_ipa:
        return Path(output_ipa).expanduser().resolve()
    return input_ipa.with_name(f"{input_ipa.stem}.appstore.ipa")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Use zsign to re-sign IPA for App Store delivery."
    )
    parser.add_argument("input_ipa", help="Path to source ipa")
    parser.add_argument("-o", "--output-ipa", help="Path to output ipa")
    parser.add_argument("--zsign-bin", default=str(DEFAULT_ZSIGN), help="Path to zsign binary")
    parser.add_argument("--cert-dir", default=str(DEFAULT_CERT_DIR), help="Directory containing p12 and mobileprovision")
    parser.add_argument("--p12", default=str(DEFAULT_P12_FILE), help="Explicit p12 path")
    parser.add_argument("--provision", default=str(DEFAULT_PROVISION_FILE), help="Explicit mobileprovision path")
    parser.add_argument(
        "--entitlements",
        default=str(DEFAULT_ENTITLEMENTS_FILE),
        help="Entitlements plist path",
    )
    parser.add_argument("--bundle-id", default=DEFAULT_BUNDLE_ID, help="Bundle ID to write")
    parser.add_argument(
        "--password",
        default=os.environ.get("ZSIGN_P12_PASSWORD", DEFAULT_P12_PASSWORD),
        help="P12 password (default: 123, or set ZSIGN_P12_PASSWORD)",
    )
    parser.add_argument("--no-check", action="store_true", help="Skip zsign -C cert/OCSP pre-check")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Run zsign -C cert/OCSP pre-check when the binary supports it",
    )
    parser.add_argument("--quiet", action="store_true", help="Pass -q to zsign")
    parser.add_argument(
        "--force",
        action="store_true",
        default=True,
        help="Pass -f to zsign (default: on, use --no-force to allow cache)",
    )
    parser.add_argument(
        "--no-force",
        action="store_false",
        dest="force",
        help="Allow zsign signature cache (not recommended for App Store)",
    )
    # App Store / altool 需要仅 SHA-256 的 CodeDirectory；另需本仓库 src 内 cdhash/CMS 等修复。
    parser.add_argument(
        "--sha256-only",
        action="store_true",
        default=True,
        help="Pass -2 to zsign (default: on for App Store)",
    )
    parser.add_argument(
        "--no-sha256-only",
        action="store_false",
        dest="sha256_only",
        help="Emit legacy SHA1+SHA256 CodeDirectories (not for App Store upload)",
    )
    args = parser.parse_args()

    input_ipa = Path(args.input_ipa).expanduser().resolve()
    if not input_ipa.is_file():
        raise FileNotFoundError(f"Input IPA not found: {input_ipa}")

    zsign_bin = Path(args.zsign_bin).expanduser().resolve()
    if not zsign_bin.is_file():
        raise FileNotFoundError(f"zsign binary not found: {zsign_bin}")

    cert_dir = Path(args.cert_dir).expanduser().resolve()
    if not cert_dir.is_dir():
        raise FileNotFoundError(f"Cert directory not found: {cert_dir}")

    p12_file = find_single_file(cert_dir, "*.p12", args.p12)
    provision_file = find_single_file(cert_dir, "*.mobileprovision", args.provision)
    entitlements_file = resolve_entitlements(args.entitlements)
    output_ipa = build_output_path(input_ipa, args.output_ipa)

    run_check = args.check or (not args.no_check and zsign_supports_cert_check(zsign_bin))
    if run_check:
        check_cmd = [str(zsign_bin), "-C", str(input_ipa)]
        print("Running cert/profile check:")
        print(" ", shlex.join(check_cmd))
        check_proc = subprocess.run(check_cmd, text=True)
        if check_proc.returncode != 0:
            return check_proc.returncode
    elif not args.no_check and not zsign_supports_cert_check(zsign_bin):
        print("Skipping cert check: zsign binary does not support -C (rebuild from this repo).")

    sign_cmd = [
        str(zsign_bin),
        "-k",
        str(p12_file),
        "-m",
        str(provision_file),
        "-b",
        args.bundle_id,

        "-o",
        str(output_ipa),
    ]
    if args.password:
        sign_cmd.extend(["-p", args.password])
    sign_cmd.extend(["-e", str(entitlements_file)])
    if args.quiet:
        sign_cmd.append("-q")
    if args.force:
        sign_cmd.append("-f")
    if args.sha256_only:
        sign_cmd.append("-2")
    sign_cmd.append(str(input_ipa))

    print("Signing command:")
    print(" ", shlex.join(sign_cmd))
    sign_proc = subprocess.run(sign_cmd, text=True)
    if sign_proc.returncode != 0:
        return sign_proc.returncode

    verify_dir = Path(output_ipa).parent / ".zsign_verify_extract"
    if verify_dir.exists():
        shutil.rmtree(verify_dir)
    subprocess.run(["unzip", "-q", str(output_ipa), "-d", str(verify_dir)], check=True)
    app_dirs = list(verify_dir.glob("Payload/*.app"))
    if not app_dirs:
        raise RuntimeError("Cannot find .app in signed IPA for entitlements verification")
    app_dir = app_dirs[0]
    with (app_dir / "Info.plist").open("rb") as fh:
        bundle_executable = plistlib.load(fh)["CFBundleExecutable"]
    main_binary = app_dir / bundle_executable
    if not main_binary.is_file():
        raise RuntimeError(f"Cannot find main binary: {main_binary}")
    verify_signed_entitlements(main_binary)
    print(f"Entitlements OK: {entitlements_file}")
    print(f"\nDone: {output_ipa}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1)
