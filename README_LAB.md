# Local Network Sniffing Lab

This project is for a safe classroom demonstration on your own machine. It compares an intentionally insecure HTTP login page with an HTTPS login page.

## Run

Install the Python dependency if needed:

```powershell
pip install -r requirements.txt
```

```powershell
python .\demo_server.py
```

Open both pages:

- Insecure HTTP: `http://127.0.0.1:8080`
- Secure HTTPS: `https://127.0.0.1:8443`

For the HTTPS page, your browser will warn about a self-signed certificate. Accept it only for this local lab.

## Wireshark Demonstration

1. Start Wireshark.
2. Capture on the loopback adapter. On Windows, this is often named `Adapter for loopback traffic capture`.
3. Visit the HTTP page and submit the form.
4. Use this display filter:

```text
tcp.port == 8080
```

5. Right-click a packet from the HTTP request and choose `Follow` > `TCP Stream`.
6. You should be able to read the submitted form body, similar to:

```text
username=student_demo&password=safe_password_123
```

7. Visit the HTTPS page and submit the form.
8. Use this display filter:

```text
tcp.port == 8443
```

9. The packets should show TLS traffic. You can see that a connection happened, but the username and password should not appear in readable plaintext.

## Presentation Point

HTTP does not encrypt request data, so anyone who can capture the traffic can read sensitive fields. HTTPS wraps HTTP inside TLS, so packet captures show encrypted TLS records instead of readable credentials.

Use only test credentials in this lab.
