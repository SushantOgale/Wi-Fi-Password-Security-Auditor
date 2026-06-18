
import argparse
import getpass
import json
from pathlib import Path

from .auditor import WifiPasswordAuditor, generate_secure_wifi_password, save_safe_report


def get_default_wordlist_dir():
    current_file = Path(__file__).resolve()
    project_root = current_file.parents[2]
    return project_root / "wordlists"


def print_report(report):
    print("\nWi-Fi Password Security Audit Report")
    print("-" * 50)
    print(f"SSID                 : {report.ssid}")
    print(f"Encryption           : {report.encryption}")
    print(f"Score                : {report.score}/100")
    print(f"Risk Level           : {report.risk_level}")
    print(f"Password Length      : {report.password_length} characters")
    print(f"Estimated Entropy    : {report.entropy_bits} bits")
    print(f"WPS Status           : {report.wps_status}")
    print(f"Router Admin Changed : {report.router_admin_changed}")
    print("\nPassword Checks")
    print("-" * 50)
    print(f"Uppercase            : {'Yes' if report.has_uppercase else 'No'}")
    print(f"Lowercase            : {'Yes' if report.has_lowercase else 'No'}")
    print(f"Numbers              : {'Yes' if report.has_digit else 'No'}")
    print(f"Special Characters   : {'Yes' if report.has_special else 'No'}")
    print(f"Repeated Characters  : {'Yes' if report.has_repeated_chars else 'No'}")
    print(f"Pattern Found        : {'Yes' if report.has_keyboard_pattern else 'No'}")
    print(f"Denylist Hit         : {'Yes' if report.has_common_password else 'No'}")
    if report.warnings:
        print("\nWarnings")
        print("-" * 50)
        for warning in report.warnings:
            print(f"- {warning}")
    print("\nRecommendations")
    print("-" * 50)
    for recommendation in report.recommendations:
        print(f"- {recommendation}")


def main():
    parser = argparse.ArgumentParser(description="Defensive Wi-Fi password and configuration security auditor.")
    parser.add_argument("--ssid", help="Your Wi-Fi SSID/network name.")
    parser.add_argument("--password", help="Wi-Fi password to audit. Avoid this option on shared systems because terminal history may store it.")
    parser.add_argument("--encryption", default="WPA2", help="Encryption type: WPA3, WPA2, WPA, WEP, OPEN, or unknown. Default: WPA2")
    parser.add_argument("--wps", default="unknown", help="WPS status: enabled, disabled, or unknown. Default: unknown")
    parser.add_argument("--admin-changed", default="unknown", help="Whether router admin password was changed: yes, no, or unknown. Default: unknown")
    parser.add_argument("--wordlist", help="Path to a custom wordlist file or directory.")
    parser.add_argument("--json", action="store_true", help="Print audit result in JSON format.")
    parser.add_argument("--save-report", help="Save a safe JSON report. The real Wi-Fi password is not stored.")
    parser.add_argument("--generate", type=int, help="Generate a strong Wi-Fi password with the given length, between 12 and 63.")
    args = parser.parse_args()
    if args.generate:
        password = generate_secure_wifi_password(args.generate)
        print("\nGenerated Strong Wi-Fi Password")
        print("-" * 50)
        print(password)
        print("\nStore this password safely in a password manager.")
        return
    ssid = args.ssid if args.ssid is not None else input("Enter Wi-Fi SSID/network name: ")
    if args.password is not None:
        password = args.password
    else:
        password = getpass.getpass("Enter Wi-Fi password to audit: ")
    wordlist = args.wordlist if args.wordlist else get_default_wordlist_dir()
    auditor = WifiPasswordAuditor(wordlist_path=wordlist)
    report = auditor.audit(
        ssid=ssid,
        password=password,
        encryption=args.encryption,
        wps_status=args.wps,
        router_admin_changed=args.admin_changed,
    )
    if args.save_report:
        saved_path = save_safe_report(report, args.save_report)
    if args.json:
        print(json.dumps(report.to_dict(), indent=4))
    else:
        print_report(report)
    if args.save_report:
        print(f"\nSafe report saved to: {saved_path}")


if __name__ == "__main__":
    main()
