
import unittest
from pathlib import Path

from src.wifi_password_security_auditor.auditor import WifiPasswordAuditor, generate_secure_wifi_password


class TestWifiPasswordAuditor(unittest.TestCase):
    def setUp(self):
        wordlist = Path(__file__).resolve().parents[1] / "wordlists"
        self.auditor = WifiPasswordAuditor(wordlist_path=wordlist)

    def test_open_wifi_is_critical_or_high(self):
        report = self.auditor.audit(ssid="HomeWiFi", password="", encryption="OPEN", wps_status="enabled", router_admin_changed="no")
        self.assertIn(report.risk_level, ["Critical", "High"])
        self.assertLess(report.score, 50)

    def test_weak_common_password_detected(self):
        report = self.auditor.audit(ssid="HomeWiFi", password="password123", encryption="WPA2", wps_status="disabled", router_admin_changed="yes")
        self.assertTrue(report.has_common_password)
        self.assertLess(report.score, 70)

    def test_strong_configuration(self):
        report = self.auditor.audit(ssid="HomeWiFi", password="Cyber@2026#SecureWifi", encryption="WPA3", wps_status="disabled", router_admin_changed="yes")
        self.assertGreaterEqual(report.score, 80)
        self.assertIn(report.risk_level, ["Low", "Very Low"])

    def test_wep_warning(self):
        report = self.auditor.audit(ssid="HomeWiFi", password="Cyber@2026#SecureWifi", encryption="WEP", wps_status="disabled", router_admin_changed="yes")
        self.assertTrue(any("WEP" in warning for warning in report.warnings))

    def test_generated_password_length(self):
        password = generate_secure_wifi_password(24)
        self.assertEqual(len(password), 24)


if __name__ == "__main__":
    unittest.main()
