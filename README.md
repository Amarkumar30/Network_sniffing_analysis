# Network Sniffing Analysis Lab

This is a safe local cybersecurity project for demonstrating how packet captures differ between insecure HTTP traffic and encrypted HTTPS traffic.

The demo starts two local login pages:

- HTTP plaintext demo: `http://127.0.0.1:8080`
- HTTPS encrypted demo: `https://127.0.0.1:8443`

Use Wireshark on the loopback adapter to show that HTTP form data can be read in plaintext, while HTTPS traffic appears as encrypted TLS records.

## Setup

```powershell
pip install -r requirements.txt
python .\demo_server.py
```

For detailed Wireshark steps, see [README_LAB.md](README_LAB.md).

Use only test credentials in this lab.
