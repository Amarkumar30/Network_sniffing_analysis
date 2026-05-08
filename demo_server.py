from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs
import html
import ssl
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


HOST = "127.0.0.1"
HTTP_PORT = 8080
HTTPS_PORT = 8443
CERT_DIR = Path(__file__).with_name("certs")
CERT_FILE = CERT_DIR / "localhost.pem"
KEY_FILE = CERT_DIR / "localhost-key.pem"


STYLE = """
:root {
    color-scheme: dark;
    font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    --panel: rgba(12, 18, 32, 0.92);
    --panel-strong: #101827;
    --line: rgba(148, 163, 184, 0.28);
    --text: #e5edf7;
    --muted: #9fb0c6;
    --input: #070d18;
}
* {
    box-sizing: border-box;
}
body {
    margin: 0;
    min-height: 100vh;
    color: var(--text);
    background:
        linear-gradient(rgba(6, 10, 20, 0.70), rgba(6, 10, 20, 0.76)),
        repeating-linear-gradient(90deg, rgba(52, 211, 153, 0.06) 0 1px, transparent 1px 80px),
        repeating-linear-gradient(0deg, rgba(96, 165, 250, 0.05) 0 1px, transparent 1px 80px),
        #050914;
}
.shell {
    width: min(1160px, calc(100vw - 32px));
    min-height: 100vh;
    margin: 0 auto;
    display: grid;
    grid-template-rows: auto 1fr auto;
    gap: 22px;
    padding: 22px 0;
}
.topbar, .statusbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    color: var(--muted);
    font-size: 0.9rem;
}
.brand {
    display: flex;
    align-items: center;
    gap: 10px;
    color: var(--text);
    font-weight: 800;
    letter-spacing: 0.02em;
}
.mark {
    width: 34px;
    height: 34px;
    display: grid;
    place-items: center;
    border: 1px solid var(--line);
    border-radius: 8px;
    background: #0d1627;
    color: var(--accent);
    font-weight: 900;
}
.layout {
    display: grid;
    grid-template-columns: minmax(0, 1.1fr) minmax(340px, 440px);
    align-items: center;
    gap: 28px;
}
.hero {
    padding: 24px 0;
}
.eyebrow {
    color: var(--accent);
    font-size: 0.86rem;
    font-weight: 800;
    text-transform: uppercase;
    letter-spacing: 0.14em;
}
h1 {
    margin: 12px 0 16px;
    max-width: 720px;
    font-size: clamp(2.1rem, 5vw, 4.7rem);
    line-height: 0.96;
    letter-spacing: 0;
}
.hero p {
    max-width: 680px;
    color: var(--muted);
    font-size: 1.05rem;
    line-height: 1.65;
}
.matrix {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 10px;
    max-width: 680px;
    margin-top: 24px;
}
.metric {
    min-height: 86px;
    padding: 14px;
    border: 1px solid var(--line);
    background: rgba(15, 23, 42, 0.72);
    border-radius: 8px;
}
.metric strong {
    display: block;
    color: var(--text);
    font-size: 1.1rem;
}
.metric span {
    display: block;
    margin-top: 6px;
    color: var(--muted);
    font-size: 0.86rem;
    line-height: 1.35;
}
main {
    border: 1px solid var(--line);
    border-radius: 8px;
    background: var(--panel);
    box-shadow: 0 24px 70px rgba(0, 0, 0, 0.42);
    overflow: hidden;
}
.panel-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    min-height: 54px;
    padding: 0 18px;
    border-bottom: 1px solid var(--line);
    background: var(--panel-strong);
}
.window-dots {
    display: flex;
    gap: 7px;
}
.window-dots span {
    width: 10px;
    height: 10px;
    border-radius: 50%;
    background: var(--muted);
}
.window-dots span:nth-child(1) { background: #ef4444; }
.window-dots span:nth-child(2) { background: #f59e0b; }
.window-dots span:nth-child(3) { background: #22c55e; }
.badge {
    display: inline-flex;
    align-items: center;
    min-height: 28px;
    padding: 0 10px;
    border: 1px solid color-mix(in srgb, var(--accent), white 20%);
    border-radius: 999px;
    color: var(--accent);
    background: color-mix(in srgb, var(--accent), transparent 88%);
    font-size: 0.78rem;
    font-weight: 800;
    text-transform: uppercase;
}
.panel-body {
    padding: 22px;
}
.notice {
    margin-bottom: 18px;
    padding: 14px;
    border: 1px solid color-mix(in srgb, var(--accent), white 10%);
    border-radius: 8px;
    background: color-mix(in srgb, var(--accent), transparent 90%);
    color: #dce8f8;
    line-height: 1.45;
}
.form-title {
    margin: 0;
    font-size: 1.55rem;
}
.form-subtitle {
    margin: 8px 0 18px;
    color: var(--muted);
    line-height: 1.5;
}
label {
    display: block;
    margin-top: 14px;
    color: #d8e2ef;
    font-weight: 800;
    font-size: 0.9rem;
}
input {
    display: block;
    width: 100%;
    margin-top: 7px;
    padding: 12px;
    border: 1px solid #29384f;
    border-radius: 6px;
    background: var(--input);
    color: var(--text);
    font: inherit;
    outline: none;
}
input:focus {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent), transparent 74%);
}
button, a.button {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 100%;
    min-height: 46px;
    margin-top: 20px;
    padding: 0 14px;
    border: 0;
    border-radius: 6px;
    background: var(--accent);
    color: #06101d;
    font: inherit;
    font-weight: 900;
    text-align: center;
    text-decoration: none;
    cursor: pointer;
}
code {
    background: rgba(226, 232, 240, 0.12);
    border: 1px solid rgba(226, 232, 240, 0.12);
    padding: 2px 6px;
    border-radius: 5px;
    color: #dce8f8;
}
.trace {
    margin-top: 18px;
    padding: 12px;
    border: 1px solid var(--line);
    border-radius: 8px;
    background: #070d18;
    color: var(--muted);
    font-family: Consolas, "Courier New", monospace;
    font-size: 0.86rem;
    line-height: 1.55;
    overflow-wrap: anywhere;
}
.trace span {
    color: var(--accent);
}
.statusbar {
    border-top: 1px solid var(--line);
    padding-top: 14px;
}
@media (max-width: 860px) {
    .layout {
        grid-template-columns: 1fr;
    }
    .matrix {
        grid-template-columns: 1fr;
    }
    h1 {
        font-size: 2.35rem;
    }
}
"""


PAGE_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{title}</title>
    <style>{style}</style>
</head>
<body style="--accent: {accent};">
    <div class="shell">
        <header class="topbar">
            <div class="brand"><span class="mark">NS</span> Network Sniffing Analysis Lab</div>
            <div>{protocol_label}</div>
        </header>
        <div class="layout">
            <section class="hero" aria-label="Lab overview">
                <div class="eyebrow">{eyebrow}</div>
                <h1>{hero_title}</h1>
                <p>{hero_copy}</p>
                <div class="matrix">
                    <div class="metric"><strong>{metric_one}</strong><span>{metric_one_copy}</span></div>
                    <div class="metric"><strong>{metric_two}</strong><span>{metric_two_copy}</span></div>
                    <div class="metric"><strong>{metric_three}</strong><span>{metric_three_copy}</span></div>
                </div>
            </section>
            <main>
                <div class="panel-head">
                    <div class="window-dots"><span></span><span></span><span></span></div>
                    <span class="badge">{badge}</span>
                </div>
                <div class="panel-body">
                    <div class="notice">{notice}</div>
                    <h2 class="form-title">{heading}</h2>
                    {content}
                </div>
            </main>
        </div>
        <footer class="statusbar">
            <span>Local-only classroom environment</span>
            <span>Wireshark filter: <code>{filter_text}</code></span>
        </footer>
    </div>
</body>
</html>"""


def render_page(
    *,
    title,
    accent,
    protocol_label,
    eyebrow,
    hero_title,
    hero_copy,
    metric_one,
    metric_one_copy,
    metric_two,
    metric_two_copy,
    metric_three,
    metric_three_copy,
    badge,
    notice,
    heading,
    content,
    filter_text,
):
    return PAGE_TEMPLATE.format(
        style=STYLE,
        title=title,
        accent=accent,
        protocol_label=protocol_label,
        eyebrow=eyebrow,
        hero_title=hero_title,
        hero_copy=hero_copy,
        metric_one=metric_one,
        metric_one_copy=metric_one_copy,
        metric_two=metric_two,
        metric_two_copy=metric_two_copy,
        metric_three=metric_three,
        metric_three_copy=metric_three_copy,
        badge=badge,
        notice=notice,
        heading=heading,
        content=content,
        filter_text=filter_text,
    )


def login_form(button_text):
    return f"""
        <p class="form-subtitle">Submit these lab-only credentials, then inspect the packet capture.</p>
        <form method="POST" action="/login">
            <label for="username">Username</label>
            <input id="username" type="text" name="username" value="student_demo" autocomplete="off">
            <label for="password">Password</label>
            <input id="password" type="password" name="password" value="safe_password_123" autocomplete="off">
            <button type="submit">{button_text}</button>
        </form>"""


def login_page(is_secure):
    if is_secure:
        return render_page(
            title="HTTPS Demo - Encrypted",
            accent="#36d399",
            protocol_label=f"TLS endpoint :{HTTPS_PORT}",
            eyebrow="Encrypted transport",
            hero_title="Same login, unreadable packet payload.",
            hero_copy=(
                "This side uses HTTPS with a local self-signed certificate. Wireshark still proves that "
                "traffic exists, but the sensitive HTTP form body is wrapped inside TLS records."
            ),
            metric_one="TLS",
            metric_one_copy="Payload is encrypted before leaving the browser.",
            metric_two="8443",
            metric_two_copy="Capture this port to compare with the HTTP demo.",
            metric_three="Protected",
            metric_three_copy="Credentials should not appear in Follow TCP Stream.",
            badge="Secure Channel",
            notice="HTTPS demo: accept the browser warning only for this local self-signed lab certificate.",
            heading="Secure Login Console",
            content=login_form("Submit over HTTPS"),
            filter_text=f"tcp.port == {HTTPS_PORT}",
        )

    return render_page(
        title="HTTP Demo - Plaintext",
        accent="#fb7185",
        protocol_label=f"Plain HTTP :{HTTP_PORT}",
        eyebrow="Plaintext transport",
        hero_title="Credentials visible in a packet capture.",
        hero_copy=(
            "This side intentionally sends a form over HTTP. In Wireshark, following the TCP stream "
            "shows the request body exactly as it crossed the loopback interface."
        ),
        metric_one="HTTP",
        metric_one_copy="No encryption is applied to the form body.",
        metric_two="8080",
        metric_two_copy="Capture this port and follow the TCP stream.",
        metric_three="Exposed",
        metric_three_copy="Username and password fields are readable.",
        badge="Insecure Channel",
        notice="HTTP demo: this page is intentionally vulnerable for classroom analysis on your own machine.",
        heading="Insecure Login Console",
        content=login_form("Submit over HTTP"),
        filter_text=f"tcp.port == {HTTP_PORT}",
    )


def success_page(is_secure, fields):
    username = html.escape(fields.get("username", [""])[0])
    if is_secure:
        content = f"""
        <p class="form-subtitle">
            Wireshark should show TLS records on port {HTTPS_PORT}, but it should not show readable form fields.
        </p>
        <div class="trace"><span>capture_result</span>: encrypted TLS application data<br>
        <span>visible_form_fields</span>: not readable in the packet stream<br>
        <span>endpoint_note</span>: the server can read data only after TLS decryption</div>
        <a class="button" href="/">Run secure capture again</a>"""
        return render_page(
            title="HTTPS Result",
            accent="#36d399",
            protocol_label=f"TLS endpoint :{HTTPS_PORT}",
            eyebrow="Encrypted result",
            hero_title="The server receives it, the sniffer cannot read it.",
            hero_copy="HTTPS protects the HTTP request body from casual packet inspection.",
            metric_one="Visible",
            metric_one_copy="IP addresses, ports, handshake, and TLS records.",
            metric_two="Hidden",
            metric_two_copy="Username and password form fields.",
            metric_three="Compare",
            metric_three_copy="Repeat the same capture on port 8080.",
            badge="TLS Protected",
            notice="Demo complete. Check the HTTPS capture and compare it with the HTTP stream.",
            heading="Secure Submission Received",
            content=content,
            filter_text=f"tcp.port == {HTTPS_PORT}",
        )

    content = f"""
        <p class="form-subtitle">
            Wireshark should show the HTTP request body on port {HTTP_PORT}. Follow the TCP stream to read it.
        </p>
        <div class="trace"><span>capture_result</span>: plaintext HTTP request body<br>
        <span>example_field</span>: username={username}<br>
        <span>risk</span>: credentials are exposed to anyone capturing the traffic</div>
        <a class="button" href="/">Run insecure capture again</a>"""
    return render_page(
        title="HTTP Result",
        accent="#fb7185",
        protocol_label=f"Plain HTTP :{HTTP_PORT}",
        eyebrow="Plaintext result",
        hero_title="The sniffer sees what the server sees.",
        hero_copy="HTTP leaves the form body readable in the captured TCP stream.",
        metric_one="Visible",
        metric_one_copy="Method, path, headers, username, and password.",
        metric_two="Risk",
        metric_two_copy="Sensitive data can be copied from the packet capture.",
        metric_three="Fix",
        metric_three_copy="Move the same workflow to HTTPS/TLS.",
        badge="Plaintext Exposed",
        notice="Demo complete. Check Wireshark now and compare this with the HTTPS page.",
        heading="Insecure Submission Received",
        content=content,
        filter_text=f"tcp.port == {HTTP_PORT}",
    )


class DemoHandler(BaseHTTPRequestHandler):
    is_secure = False

    def do_GET(self):
        self.send_html(login_page(self.is_secure))

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body_bytes = self.rfile.read(length)
        body = body_bytes.decode("utf-8", errors="replace")
        fields = parse_qs(body)

        protocol = "HTTPS" if self.is_secure else "HTTP"
        print(f"\n[{protocol} POST received by server]")
        if self.is_secure:
            print("Form submitted over HTTPS. The server can read it after TLS decryption.")
            print("In Wireshark, the packet payload should appear as TLS application data.")
        else:
            print(body)

        self.send_html(success_page(self.is_secure, fields))

    def send_html(self, html_body):
        body = html_body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


class HttpHandler(DemoHandler):
    is_secure = False


class HttpsHandler(DemoHandler):
    is_secure = True


def ensure_self_signed_cert():
    if CERT_FILE.exists() and KEY_FILE.exists():
        return

    CERT_DIR.mkdir(exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Local Cybersecurity Lab"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(__import__("ipaddress").ip_address(HOST))]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    KEY_FILE.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    CERT_FILE.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def run_http():
    server = ThreadingHTTPServer((HOST, HTTP_PORT), HttpHandler)
    print(f"Insecure HTTP demo:  http://{HOST}:{HTTP_PORT}")
    server.serve_forever()


def run_https():
    ensure_self_signed_cert()
    server = ThreadingHTTPServer((HOST, HTTPS_PORT), HttpsHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print(f"Secure HTTPS demo:    https://{HOST}:{HTTPS_PORT}")
    print("Browser note: accept the self-signed certificate warning for this local lab.")
    server.serve_forever()


if __name__ == "__main__":
    print("Local network sniffing lab for safe classroom use")
    print("Start Wireshark capture on the loopback interface.")
    print(f"HTTP filter:  tcp.port == {HTTP_PORT}")
    print(f"HTTPS filter: tcp.port == {HTTPS_PORT}")
    print()

    threading.Thread(target=run_http, daemon=True).start()
    threading.Thread(target=run_https, daemon=True).start()

    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\nServers stopped.")
