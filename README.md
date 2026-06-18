# Wi-Fi Password Security Auditor

A defensive Python project for checking the security strength of your own Wi-Fi password and Wi-Fi configuration.

This project does **not** crack Wi-Fi passwords.
It does **not** capture handshakes.
It does **not** scan nearby networks.
It does **not** send data anywhere.

It only checks information that you provide locally.

## Features

- Checks Wi-Fi password strength
- Checks WPA/WPA2/WPA3/Open/WEP security risk
- Detects weak/common passwords
- Detects repeated characters
- Detects keyboard patterns like `qwerty` and `123456`
- Checks WPS risk
- Checks whether router admin password was changed
- Gives a score out of 100
- Gives human-readable recommendations
- Supports JSON output
- Can save a safe audit report without storing the real password
- Can generate a strong Wi-Fi password locally

## Project Structure

```text
wifi_password_security_auditor/
├── src/
│   └── wifi_password_security_auditor/
│       ├── __init__.py
│       ├── auditor.py
│       └── cli.py
├── tests/
│   └── test_auditor.py
├── wordlists/
│   └── common_wifi_passwords.txt
├── reports/
├── requirements.txt
└── README.md
```

## How to Run

From the project folder:

```bash
python -m src.wifi_password_security_auditor.cli
```

Direct command example:

```bash
python -m src.wifi_password_security_auditor.cli --ssid "HomeWiFi" --password "MyWiFi@2026Secure" --encryption WPA2 --wps disabled --admin-changed yes
```

JSON output:

```bash
python -m src.wifi_password_security_auditor.cli --ssid "HomeWiFi" --password "MyWiFi@2026Secure" --encryption WPA2 --wps disabled --admin-changed yes --json
```

Save a safe report:

```bash
python -m src.wifi_password_security_auditor.cli --ssid "HomeWiFi" --password "MyWiFi@2026Secure" --encryption WPA2 --wps disabled --admin-changed yes --save-report reports/audit_report.json
```

Generate a strong Wi-Fi password:

```bash
python -m src.wifi_password_security_auditor.cli --generate 24
```

## Run Tests

```bash
python -m unittest discover tests
```

## Security Notes

For home Wi-Fi, prefer:

- WPA3-Personal if available
- WPA2-AES if WPA3 is not available
- 16 to 24+ character Wi-Fi password
- WPS disabled
- Router admin password changed from default
- Router firmware updated
- Guest network for visitors/IoT devices

Avoid:

- Open Wi-Fi
- WEP
- WPA/TKIP
- Short passwords
- Passwords based on your name, phone number, birthday, SSID, or address
- Passwords like `password123`, `12345678`, `qwerty123`, or `admin123`

## Ethical Use

Use this project only to audit your own Wi-Fi password and configuration.
Do not use it to test, guess, collect, crack, or attack networks that you do not own or do not have permission to assess.
