
import json
import math
import re
import secrets
import string
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional


KEYBOARD_PATTERNS = [
    "qwerty", "asdf", "zxcv", "1234", "12345", "123456",
    "abcdef", "password", "admin", "wifi", "router",
]


@dataclass
class WifiAuditReport:
    ssid: str
    encryption: str
    score: int
    risk_level: str
    password_length: int
    entropy_bits: float
    has_uppercase: bool
    has_lowercase: bool
    has_digit: bool
    has_special: bool
    has_repeated_chars: bool
    has_keyboard_pattern: bool
    has_common_password: bool
    wps_status: str
    router_admin_changed: str
    warnings: list
    recommendations: list

    def to_dict(self):
        return asdict(self)


class WifiPasswordAuditor:
    def __init__(self, wordlist_path: Optional[str] = None):
        self.common_passwords = set()
        if wordlist_path:
            self.common_passwords = self._load_wordlist(wordlist_path)

    def _load_wordlist(self, wordlist_path):
        path = Path(wordlist_path)
        passwords = set()
        if not path.exists():
            return passwords
        if path.is_file():
            files = [path]
        else:
            files = sorted(list(path.glob("*.txt")) + list(path.glob("*.list")))
        for file_path in files:
            try:
                lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
                for line in lines:
                    value = line.strip().lower()
                    if value:
                        passwords.add(value)
            except OSError:
                continue
        return passwords

    def _charset_size(self, password):
        size = 0
        if re.search(r"[a-z]", password):
            size += 26
        if re.search(r"[A-Z]", password):
            size += 26
        if re.search(r"\d", password):
            size += 10
        if re.search(r"[^a-zA-Z0-9]", password):
            size += 32
        return size

    def estimate_entropy(self, password):
        charset = self._charset_size(password)
        if not password or charset == 0:
            return 0.0
        return round(len(password) * math.log2(charset), 2)

    def _has_repeated_chars(self, password):
        return bool(re.search(r"(.)\1\1", password))

    def _has_keyboard_pattern(self, password):
        lower = password.lower()
        return any(pattern in lower for pattern in KEYBOARD_PATTERNS)

    def _has_common_password(self, password):
        lower = password.lower()
        normalized = re.sub(r"[^a-z0-9]", "", lower)
        return lower in self.common_passwords or normalized in self.common_passwords

    def _check_ssid_risks(self, ssid):
        warnings = []
        recommendations = []
        if not ssid.strip():
            warnings.append("SSID is empty or not provided.")
            recommendations.append("Use a normal SSID that does not expose personal details.")
            return warnings, recommendations
        lower = ssid.lower()
        risky_words = ["password", "admin", "router", "default", "home address", "phone"]
        for word in risky_words:
            if word in lower:
                warnings.append(f"SSID contains risky word: {word}")
                recommendations.append("Avoid SSID names that reveal router details, passwords, or personal information.")
                break
        if len(ssid) > 32:
            warnings.append("SSID is longer than the normal 32-character Wi-Fi SSID limit.")
            recommendations.append("Use an SSID of 32 characters or fewer.")
        return warnings, recommendations

    def _score_encryption(self, encryption, warnings, recommendations):
        enc = encryption.upper().strip()
        if enc in {"WPA3", "WPA3-PERSONAL"}:
            return 25
        if enc in {"WPA2", "WPA2-AES"}:
            return 22
        if enc == "WPA2/WPA3":
            return 23
        if enc in {"WPA", "WPA-TKIP"}:
            warnings.append("WPA/TKIP is outdated and weaker than WPA2-AES or WPA3.")
            recommendations.append("Use WPA3-Personal or WPA2-AES.")
            return 8
        if enc == "WEP":
            warnings.append("WEP is broken and should not be used.")
            recommendations.append("Change router security mode to WPA2-AES or WPA3.")
            return 0
        if enc == "OPEN":
            warnings.append("Open Wi-Fi has no password protection.")
            recommendations.append("Enable WPA2-AES or WPA3-Personal immediately.")
            return 0
        warnings.append("Encryption type is unknown.")
        recommendations.append("Confirm your router uses WPA2-AES or WPA3-Personal.")
        return 10

    def _score_password(self, password, checks, entropy, warnings, recommendations):
        score = 0
        length = len(password)
        if length == 0:
            warnings.append("No Wi-Fi password was provided.")
            recommendations.append("Set a strong Wi-Fi password.")
            return 0
        if length < 8:
            warnings.append("Wi-Fi password is shorter than 8 characters.")
            recommendations.append("Use at least 12 characters; 16 to 24+ is better.")
        elif length < 12:
            warnings.append("Wi-Fi password meets the minimum length but is still short.")
            recommendations.append("Use 16 to 24+ characters for stronger Wi-Fi security.")
            score += 10
        elif length < 16:
            score += 18
            recommendations.append("Password length is decent. 16+ characters is better.")
        elif length <= 63:
            score += 28
        else:
            warnings.append("Wi-Fi password is longer than 63 characters, which may not be accepted by many routers.")
            recommendations.append("Use a Wi-Fi password between 16 and 63 characters.")
            score += 15
        if checks["has_uppercase"]:
            score += 7
        else:
            recommendations.append("Add uppercase letters.")
        if checks["has_lowercase"]:
            score += 7
        else:
            recommendations.append("Add lowercase letters.")
        if checks["has_digit"]:
            score += 7
        else:
            recommendations.append("Add numbers.")
        if checks["has_special"]:
            score += 8
        else:
            recommendations.append("Add special characters such as @, #, $, %, or !.")
        if entropy >= 100:
            score += 15
        elif entropy >= 80:
            score += 12
        elif entropy >= 60:
            score += 8
        elif entropy >= 40:
            score += 4
        else:
            warnings.append("Password entropy is low.")
            recommendations.append("Use a longer, less predictable password.")
        if checks["has_repeated_chars"]:
            score -= 8
            warnings.append("Password contains repeated characters.")
            recommendations.append("Avoid repeated patterns like 111, aaa, or !!!.")
        if checks["has_keyboard_pattern"]:
            score -= 15
            warnings.append("Password contains common keyboard or predictable patterns.")
            recommendations.append("Avoid patterns like qwerty, 123456, password, admin, router, or wifi.")
        if checks["has_common_password"]:
            score -= 30
            warnings.append("Password appears in the common Wi-Fi password denylist.")
            recommendations.append("Do not use common passwords. Create a unique Wi-Fi password.")
        return max(0, min(65, score))

    def _score_wps(self, wps_status, warnings, recommendations):
        status = wps_status.lower().strip()
        if status in {"disabled", "off", "no"}:
            return 5
        if status in {"enabled", "on", "yes"}:
            warnings.append("WPS is enabled. WPS can weaken Wi-Fi security.")
            recommendations.append("Disable WPS in router settings.")
            return 0
        recommendations.append("Check router settings and disable WPS if it is enabled.")
        return 2

    def _score_admin_password(self, router_admin_changed, warnings, recommendations):
        status = router_admin_changed.lower().strip()
        if status in {"yes", "changed", "true"}:
            return 5
        if status in {"no", "default", "false"}:
            warnings.append("Router admin password may still be default.")
            recommendations.append("Change the router admin password from the default value.")
            return 0
        recommendations.append("Confirm whether the router admin password was changed from default.")
        return 2

    def _risk_level(self, score):
        if score < 30:
            return "Critical"
        if score < 50:
            return "High"
        if score < 70:
            return "Medium"
        if score < 85:
            return "Low"
        return "Very Low"

    def audit(self, ssid, password, encryption="WPA2", wps_status="unknown", router_admin_changed="unknown"):
        ssid = ssid or ""
        password = password or ""
        encryption = encryption or "unknown"
        entropy = self.estimate_entropy(password)
        checks = {
            "has_uppercase": bool(re.search(r"[A-Z]", password)),
            "has_lowercase": bool(re.search(r"[a-z]", password)),
            "has_digit": bool(re.search(r"\d", password)),
            "has_special": bool(re.search(r"[^a-zA-Z0-9]", password)),
            "has_repeated_chars": self._has_repeated_chars(password),
            "has_keyboard_pattern": self._has_keyboard_pattern(password),
            "has_common_password": self._has_common_password(password),
        }
        warnings = []
        recommendations = []
        ssid_warnings, ssid_recommendations = self._check_ssid_risks(ssid)
        warnings.extend(ssid_warnings)
        recommendations.extend(ssid_recommendations)
        score = 0
        score += self._score_encryption(encryption, warnings, recommendations)
        score += self._score_password(password, checks, entropy, warnings, recommendations)
        score += self._score_wps(wps_status, warnings, recommendations)
        score += self._score_admin_password(router_admin_changed, warnings, recommendations)
        score = max(0, min(100, score))
        risk_level = self._risk_level(score)
        if score >= 85:
            recommendations.append("Configuration looks strong. Keep router firmware updated.")
        elif score >= 70:
            recommendations.append("Security is good, but review the warnings to improve it further.")
        else:
            recommendations.append("Improve the weak areas before relying on this Wi-Fi network for sensitive use.")
        recommendations = list(dict.fromkeys(recommendations))
        warnings = list(dict.fromkeys(warnings))
        return WifiAuditReport(
            ssid=ssid,
            encryption=encryption.upper().strip(),
            score=score,
            risk_level=risk_level,
            password_length=len(password),
            entropy_bits=entropy,
            has_uppercase=checks["has_uppercase"],
            has_lowercase=checks["has_lowercase"],
            has_digit=checks["has_digit"],
            has_special=checks["has_special"],
            has_repeated_chars=checks["has_repeated_chars"],
            has_keyboard_pattern=checks["has_keyboard_pattern"],
            has_common_password=checks["has_common_password"],
            wps_status=wps_status,
            router_admin_changed=router_admin_changed,
            warnings=warnings,
            recommendations=recommendations,
        )


def generate_secure_wifi_password(length=24):
    if length < 12:
        length = 12
    if length > 63:
        length = 63
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    while True:
        password = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            re.search(r"[a-z]", password)
            and re.search(r"[A-Z]", password)
            and re.search(r"\d", password)
            and re.search(r"[^a-zA-Z0-9]", password)
        ):
            return password


def save_safe_report(report, output_path):
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = report.to_dict()
    data["note"] = "The actual Wi-Fi password is not stored in this report."
    path.write_text(json.dumps(data, indent=4), encoding="utf-8")
    return path
