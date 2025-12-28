import os
import http.server
import socketserver
import threading
import socket
import logging
from pathlib import Path
from tkinter import Tk, StringVar, BooleanVar, Text, END, Toplevel
from tkinter import filedialog, messagebox
from tkinter import Label, Frame, Checkbutton
from tkinter import ttk
import pyperclip
import base64
import re
import time
import atexit
import hashlib
import hmac
import secrets
import ssl
from collections import defaultdict
from datetime import datetime, timedelta  # used for cert validity
import webbrowser

# === Metadata / Credits ===
APP_NAME = "PySecureFS"
APP_AUTHOR = "Mithras Kuipers"
APP_GITHUB_URL = "https://github.com/mithraskuipers"
APP_LINKEDIN_URL = "https://www.linkedin.com/in/mithraskuipers"

# === Log file configuration ===
LOG_FILE = "pysecurefs.log"

# --- cryptography for pure-Python self-signed certificate generation ---
try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    CRYPTOGRAPHY_AVAILABLE = True
except Exception:
    CRYPTOGRAPHY_AVAILABLE = False

# === Security configuration (tweakable from one place) ===
SECURITY_CONFIG = {
    # Login / lockout
    "MAX_LOGIN_ATTEMPTS": 5,
    "LOCKOUT_DURATION": 300,  # Seconds an IP is locked out

    # Rate limiting
    "RATE_LIMIT_WINDOW": 60,  # Seconds
    "MAX_REQUESTS_PER_WINDOW": 20,

    # Sessions
    "SESSION_DURATION": 3600,  # Seconds

    # Password hashing
    "PBKDF2_ITERATIONS": 100000,
    "PBKDF2_ALGO": "sha256",
    "SALT_BYTES": 16,

    # Cleanup
    "SESSION_CLEANUP_INTERVAL": 300,  # Seconds
}

MAX_LOGIN_ATTEMPTS = SECURITY_CONFIG["MAX_LOGIN_ATTEMPTS"]
LOCKOUT_DURATION = SECURITY_CONFIG["LOCKOUT_DURATION"]
RATE_LIMIT_WINDOW = SECURITY_CONFIG["RATE_LIMIT_WINDOW"]
MAX_REQUESTS_PER_WINDOW = SECURITY_CONFIG["MAX_REQUESTS_PER_WINDOW"]
SESSION_DURATION = SECURITY_CONFIG["SESSION_DURATION"]
PBKDF2_ITERATIONS = SECURITY_CONFIG["PBKDF2_ITERATIONS"]
PBKDF2_ALGO = SECURITY_CONFIG["PBKDF2_ALGO"]
SALT_BYTES = SECURITY_CONFIG["SALT_BYTES"]
SESSION_CLEANUP_INTERVAL = SECURITY_CONFIG["SESSION_CLEANUP_INTERVAL"]

# === HTTPS / TLS configuration ===
HTTPS_CONFIG = {
    "ENABLE_HTTPS_DEFAULT": False,
    "CERT_FILE_DEFAULT": "server.crt",
    "KEY_FILE_DEFAULT": "server.key",
    "SSL_PROTOCOL": ssl.PROTOCOL_TLS_SERVER,
    "CERT_DAYS": 365,
}

SSL_PROTOCOL = HTTPS_CONFIG["SSL_PROTOCOL"]
CERT_DAYS = HTTPS_CONFIG["CERT_DAYS"]

# Storage for security tracking
login_attempts = defaultdict(list)
locked_accounts = {}
active_sessions = {}
request_counts = defaultdict(list)

# --- Optional GUI log window handler ---
class TkTextHandler(logging.Handler):
    def __init__(self, text_widget_getter):
        super().__init__()
        self.text_widget_getter = text_widget_getter

    def emit(self, record):
        msg = self.format(record)
        widget = self.text_widget_getter()
        if widget is None:
            return

        def append():
            try:
                widget.configure(state="normal")
                widget.insert(END, msg + "\n")
                widget.see(END)
                widget.configure(state="disabled")
            except Exception:
                pass

        try:
            if root and root.winfo_exists():
                root.after(0, append)
        except Exception:
            pass


def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(SALT_BYTES)

    pwd_hash = hashlib.pbkdf2_hmac(
        PBKDF2_ALGO,
        password.encode("utf-8"),
        salt.encode("utf-8"),
        PBKDF2_ITERATIONS,
    )
    return f"{salt}${pwd_hash.hex()}"


def verify_password(stored_hash, provided_password):
    try:
        salt, pwd_hash = stored_hash.split("$")
        new_hash = hashlib.pbkdf2_hmac(
            PBKDF2_ALGO,
            provided_password.encode("utf-8"),
            salt.encode("utf-8"),
            PBKDF2_ITERATIONS,
        )
        return hmac.compare_digest(pwd_hash, new_hash.hex())
    except Exception:
        return False


def is_rate_limited(ip_address):
    now = time.time()
    request_counts[ip_address] = [
        ts for ts in request_counts[ip_address] if now - ts < RATE_LIMIT_WINDOW
    ]
    if len(request_counts[ip_address]) >= MAX_REQUESTS_PER_WINDOW:
        return True
    request_counts[ip_address].append(now)
    return False


def is_locked_out(ip_address):
    if ip_address in locked_accounts:
        if time.time() < locked_accounts[ip_address]:
            return True
        del locked_accounts[ip_address]
        login_attempts[ip_address] = []
    return False


def record_failed_login(ip_address):
    now = time.time()
    login_attempts[ip_address] = [
        ts for ts in login_attempts[ip_address] if now - ts < LOCKOUT_DURATION
    ]
    login_attempts[ip_address].append(now)

    if len(login_attempts[ip_address]) >= MAX_LOGIN_ATTEMPTS:
        locked_accounts[ip_address] = now + LOCKOUT_DURATION
        logger.warning(
            f"IP {ip_address} locked out due to too many failed login attempts"
        )
        return True
    return False


def record_successful_login(ip_address):
    if ip_address in login_attempts:
        login_attempts[ip_address] = []


def create_session(username):
    token = secrets.token_urlsafe(32)
    expiry = time.time() + SESSION_DURATION
    active_sessions[token] = (username, expiry)
    return token


def validate_session(token):
    if token in active_sessions:
        username, expiry = active_sessions[token]
        if time.time() < expiry:
            return username
        del active_sessions[token]
    return None


def cleanup_expired_sessions():
    now = time.time()
    expired = [
        token for token, (_, expiry) in active_sessions.items() if now >= expiry
    ]
    for token in expired:
        del active_sessions[token]


# === Logging configuration ===
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

console_handler = logging.StreamHandler()
console_handler.setFormatter(
    logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
)
logger.addHandler(console_handler)

file_handler = logging.FileHandler(LOG_FILE, mode="a", encoding="utf-8")
file_handler.setFormatter(
    logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
)
logger.addHandler(file_handler)

PORT = 8000
server_thread = None
httpd = None
server_running = False
stop_flag = threading.Event()
cleanup_done = False

UPLOAD_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>File Server</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 900px; margin: 40px auto; padding: 20px; background: #f5f7fa; }}
        h1 {{ color: #2c3e50; }}
        h2 {{ color: #34495e; margin-bottom: 20px; }}
        .upload-section {{ background: #ffffff; padding: 25px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.06); margin-bottom: 40px; }}
        .hidden {{ display: none; }}
        .info-msg {{ color: #1976d2; font-size: 0.95em; margin: 10px 0 20px 0; }}
        input[type="file"] {{ display: block; margin: 15px 0; padding: 10px; width: 100%; box-sizing: border-box; border-radius: 6px; border: 1px solid #ccc; }}
        input[type="submit"] {{ background: #2ecc71; color: white; padding: 12px 24px; border: none; border-radius: 6px; cursor: pointer; font-size: 15px; font-weight: bold; }}
        input[type="submit"]:hover {{ background: #27ae60; }}
        input[type="submit"]:disabled {{ background: #bdc3c7; cursor: not-allowed; }}
        .error-msg {{ color: #c0392b; background: #fdecea; padding: 12px; border-radius: 6px; margin: 15px 0; display: none; border-left: 4px solid #c0392b; }}
        ul {{ list-style-type: none; padding: 0; }}
        li {{ padding: 12px; margin: 8px 0; background: #ffffff; border-radius: 8px; box-shadow: 0 1px 5px rgba(0,0,0,0.04); display: flex; justify-content: space-between; align-items: center; }}
        a {{ color: #2980b9; text-decoration: none; font-weight: bold; }}
        a:hover {{ text-decoration: underline; }}
        small {{ color: #7f8c8d; }}
        hr {{ margin: 40px 0 20px 0; border: none; border-top: 1px solid #e0e6ed; }}
        .footer {{ margin-top: 30px; font-size: 0.85em; color: #95a5a6; }}
    </style>
</head>
<body>
    <h1>PySecureFS</h1>
    <div id="uploadSection" class="upload-section {upload_class}">
        <h2>📁 Upload a File</h2>
        <div class="info-msg">Maximum allowed file size: <strong>{max_upload_mb} MB</strong></div>
        <form id="uploadForm" enctype="multipart/form-data" method="post">
            <input type="file" name="file" id="fileInput" required>
            <input type="submit" value="Upload File" id="submitBtn">
        </form>
        <div id="errorMsg" class="error-msg"></div>
    </div>
    <hr>
    <h2>📂 Available Files</h2>
    <ul>
        {file_list}
    </ul>
    <div class="footer">
        Built by {app_author}
    </div>
    <script>
        const form = document.getElementById('uploadForm');
        const fileInput = document.getElementById('fileInput');
        const submitBtn = document.getElementById('submitBtn');
        const errorMsg = document.getElementById('errorMsg');
        const maxSizeMB = {max_upload_mb};
        const maxSizeBytes = maxSizeMB * 1024 * 1024;
        function showError(message) {{
            errorMsg.textContent = message;
            errorMsg.style.display = 'block';
            submitBtn.disabled = false;
        }}
        function clearError() {{
            errorMsg.style.display = 'none';
        }}
        fileInput.addEventListener('change', function() {{
            clearError();
            if (fileInput.files.length > 0) {{
                const file = fileInput.files[0];
                if (file.size > maxSizeBytes) {{
                    showError(`Error: "${{file.name}}" is too large. Maximum size is ${{maxSizeMB}} MB.`);
                    fileInput.value = '';
                    submitBtn.disabled = true;
                }} else {{
                    submitBtn.disabled = false;
                }}
            }}
        }});
        form.addEventListener('submit', function(e) {{
            if (fileInput.files.length === 0) return;
            const file = fileInput.files[0];
            if (file.size > maxSizeBytes) {{
                e.preventDefault();
                showError(`Upload blocked: File exceeds the ${{maxSizeMB}} MB limit.`);
            }} else {{
                submitBtn.disabled = true;
                submitBtn.value = "Uploading...";
                clearError();
            }}
        }});
    </script>
</body>
</html>"""


class AuthHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(
        self,
        *args,
        directory=None,
        username=None,
        password=None,
        upload_enabled=False,
        max_upload_mb=1000,
        **kwargs,
    ):
        self.custom_directory = directory
        self.username = username
        self.password_hash = hash_password(password) if password else None
        self.auth_enabled = bool(username and password)
        self.upload_enabled = upload_enabled
        self.max_upload_mb = max_upload_mb
        super().__init__(*args, directory=directory, **kwargs)

    def log_message(self, format, *args):
        logger.info("%s - %s", self.address_string(), format % args)

    def get_client_ip(self):
        forwarded = self.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return self.client_address[0]

    def send_auth_headers(self, message="Authentication required"):
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="File Server Access"')
        self.send_header("Content-type", "text/html")
        self.end_headers()
        html = f"<html><body><h1>401 Unauthorized</h1><p>{message}</p></body></html>"
        self.wfile.write(html.encode())

    def send_locked_out_response(self, remaining_time):
        self.send_response(429)
        self.send_header("Content-type", "text/html")
        self.send_header("Retry-After", str(int(remaining_time)))
        self.end_headers()
        minutes = int(remaining_time // 60)
        seconds = int(remaining_time % 60)
        html = f"""<html><body>
        <h1>429 Too Many Requests</h1>
        <p>Too many failed login attempts. Please try again in {minutes}m {seconds}s.</p>
        </body></html>"""
        self.wfile.write(html.encode())

    def send_rate_limited_response(self):
        self.send_response(429)
        self.send_header("Content-type", "text/html")
        self.send_header("Retry-After", str(RATE_LIMIT_WINDOW))
        self.end_headers()
        html = """<html><body>
        <h1>429 Too Many Requests</h1>
        <p>Rate limit exceeded. Please slow down your requests.</p>
        </body></html>"""
        self.wfile.write(html.encode())

    def check_credentials(self):
        if not self.auth_enabled:
            return True

        client_ip = self.get_client_ip()

        if is_rate_limited(client_ip):
            logger.warning("Rate limit exceeded for %s", client_ip)
            self.send_rate_limited_response()
            return None

        if is_locked_out(client_ip):
            remaining = locked_accounts[client_ip] - time.time()
            logger.warning("Locked out IP %s attempted access", client_ip)
            self.send_locked_out_response(remaining)
            return None

        cookie = self.headers.get("Cookie")
        if cookie:
            for part in cookie.split(";"):
                part = part.strip()
                if part.startswith("session="):
                    token = part.split("=", 1)[1]
                    username = validate_session(token)
                    if username:
                        return True

        auth_header = self.headers.get("Authorization")
        if auth_header and auth_header.startswith("Basic "):
            try:
                decoded = base64.b64decode(auth_header.split(" ")[1]).decode("utf-8")
                username, password = decoded.split(":", 1)

                if (
                    username == self.username
                    and verify_password(self.password_hash, password)
                ):
                    record_successful_login(client_ip)
                    logger.info("Successful login from %s", client_ip)
                    token = create_session(username)
                    self.session_token = token
                    return True

                is_locked = record_failed_login(client_ip)
                remaining_attempts = MAX_LOGIN_ATTEMPTS - len(login_attempts[client_ip])

                if is_locked:
                    logger.warning("Account locked for %s", client_ip)
                else:
                    logger.warning(
                        "Failed login from %s (%s attempts remaining)",
                        client_ip,
                        remaining_attempts,
                    )
                return False
            except Exception as e:
                logger.error("Auth error: %s", e)
                return False

        return False

    def send_with_session_cookie(self):
        if hasattr(self, "session_token"):
            self.send_header(
                "Set-Cookie",
                (
                    f"session={self.session_token}; HttpOnly; SameSite=Strict; "
                    f"Max-Age={SESSION_DURATION}"
                ),
            )

    def do_GET(self):
        auth_result = self.check_credentials()
        if auth_result is None:
            return
        if not auth_result:
            self.send_auth_headers()
            return

        if self.path == "/":
            try:
                folder = self.custom_directory
                files = [
                    f
                    for f in os.listdir(folder)
                    if not f.startswith(".")
                    and os.path.isfile(os.path.join(folder, f))
                ]
                files.sort()

                file_list = "".join(
                    f"<li><span>📄 <a href='/{f}'>{f}</a></span> "
                    f"<small>{self._get_file_size(os.path.join(folder, f))}</small></li>"
                    for f in files
                )

                if not file_list:
                    file_list = "<li><em>No files available yet.</em></li>"

                upload_class = "" if self.upload_enabled else "hidden"
                page = UPLOAD_PAGE.format(
                    file_list=file_list,
                    upload_class=upload_class,
                    max_upload_mb=self.max_upload_mb,
                    app_author=APP_AUTHOR,
                ).encode("utf-8")

                self.send_response(200)
                self.send_with_session_cookie()
                self.send_header("Content-type", "text/html; charset=utf-8")
                self.send_header("Content-length", len(page))
                self.end_headers()
                self.wfile.write(page)
            except Exception as e:
                logger.error("Error generating page: %s", e)
                self.send_error(500, f"Internal Server Error: {str(e)}")
        else:
            super().do_GET()

    def do_POST(self):
        if not self.upload_enabled:
            self.send_error(403, "Upload is disabled")
            return

        auth_result = self.check_credentials()
        if auth_result is None:
            return
        if not auth_result:
            self.send_auth_headers()
            return

        try:
            content_length = int(self.headers["Content-Length"])
            max_bytes = self.max_upload_mb * 1024 * 1024

            if content_length > max_bytes:
                self.send_error(413, f"File too large. Max: {self.max_upload_mb} MB")
                return

            content_type = self.headers.get("Content-Type", "")
            if "boundary=" not in content_type:
                self.send_error(400, "Invalid multipart request")
                return

            boundary = content_type.split("boundary=")[1].encode()
            data = self.rfile.read(content_length)
            parts = data.split(b"--" + boundary)
            uploaded = False

            for part in parts:
                if b'filename="' in part:
                    try:
                        headers, body = part.split(b"\r\n\r\n", 1)
                    except ValueError:
                        continue
                    body = body.rstrip(b"\r\n--")
                    match = re.search(b'filename="([^"]+)"', headers)
                    if not match:
                        continue
                    filename = match.group(1).decode("utf-8")
                    filename = os.path.basename(filename)

                    if not filename or ".." in filename:
                        self.send_error(400, "Invalid filename")
                        return

                    filepath = os.path.join(self.custom_directory, filename)

                    if os.path.exists(filepath):
                        base, ext = os.path.splitext(filename)
                        i = 1
                        while os.path.exists(filepath):
                            filename = f"{base}_{i}{ext}"
                            filepath = os.path.join(self.custom_directory, filename)
                            i += 1

                    with open(filepath, "wb") as f:
                        f.write(body)

                    logger.info("Uploaded: %s (%s bytes)", filename, len(body))
                    uploaded = True

            if uploaded:
                self.send_response(303)
                self.send_header("Location", "/")
                self.end_headers()
            else:
                self.send_error(400, "No file received")

        except Exception as e:
            logger.error("Upload error: %s", e)
            self.send_error(500, "Upload failed")

    def _get_file_size(self, path):
        try:
            size = os.path.getsize(path)
            for unit in ["B", "KB", "MB", "GB"]:
                if size < 1024:
                    return f"{size:.1f} {unit}"
                size /= 1024
            return f"{size:.1f} TB"
        except Exception:
            return "Unknown"


def periodic_cleanup():
    while not stop_flag.is_set():
        time.sleep(SESSION_CLEANUP_INTERVAL)
        cleanup_expired_sessions()
        logger.debug("Cleaned up expired sessions")


class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True

    def server_bind(self):
        # Bind to all interfaces so other machines on the LAN can reach it
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        super().server_bind()


def generate_self_signed_cert_python(cert_file, key_file):
    if os.path.exists(cert_file) and os.path.exists(key_file):
        logger.info("Certificate and key already exist: %s, %s", cert_file, key_file)
        return True

    if not CRYPTOGRAPHY_AVAILABLE:
        logger.error("cryptography library not available.")
        return False

    try:
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "NL"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Local"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Local"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Local File Server"),
                x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
            ]
        )

        now = datetime.utcnow()
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=CERT_DAYS))
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.DNSName("localhost"),
                    ]
                ),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )

        with open(key_file, "wb") as f:
            f.write(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

        with open(cert_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        logger.info("Self-signed certificate created: %s, %s", cert_file, key_file)
        return True
    except Exception as e:
        logger.error("Error generating certificate: %s", e)
        return False


def start_server(
    folder,
    port,
    username=None,
    password=None,
    upload_enabled=False,
    max_upload_mb=1000,
    enable_https=False,
    cert_file=None,
    key_file=None,
):
    global httpd, server_running
    cleanup_thread = threading.Thread(target=periodic_cleanup, daemon=True)
    cleanup_thread.start()

    def handler(*args, **kwargs):
        return AuthHTTPRequestHandler(
            *args,
            directory=folder,
            username=username,
            password=password,
            upload_enabled=upload_enabled,
            max_upload_mb=max_upload_mb,
            **kwargs,
        )

    try:
        # Bind to all interfaces ("") so it's reachable from other machines
        httpd = ReusableTCPServer(("", port), handler)

        if enable_https:
            cert_file = cert_file or HTTPS_CONFIG["CERT_FILE_DEFAULT"]
            key_file = key_file or HTTPS_CONFIG["KEY_FILE_DEFAULT"]

            if not (os.path.isfile(cert_file) and os.path.isfile(key_file)):
                logger.error(
                    "HTTPS enabled but certificate or key file not found: %s, %s",
                    cert_file,
                    key_file,
                )
                raise FileNotFoundError("Missing TLS certificate or key file")

            context = ssl.SSLContext(SSL_PROTOCOL)
            # Allow older TLS versions and weaker ciphers if necessary for LAN use
            context.load_cert_chain(certfile=cert_file, keyfile=key_file)
            httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
            logger.info("HTTPS enabled using cert=%s key=%s", cert_file, key_file)

        server_running = True
        logger.info("Server successfully started on port %s", port)
        while not stop_flag.is_set():
            httpd.handle_request()
    except OSError as e:
        if getattr(e, "errno", None) == 98 or "Address already in use" in str(e):
            error_msg = f"⚠️ Port {port} is already in use!"
            suggestion = "Please try a different port (e.g., 8001, 8080)."
            full_msg = f"{error_msg} {suggestion}"
            logger.warning(full_msg)
            if root and root.winfo_exists():
                root.after(
                    0,
                    lambda msg=full_msg: (
                        status_label.config(
                            text=msg,
                            foreground="#d35400",
                        ),
                        start_btn.config(state="normal"),
                        root.after(
                            10000,
                            lambda: (
                                status_label.config(
                                    text="Ready", foreground="#27ae60"
                                )
                                if not server_running
                                else None
                            ),
                        ),
                    ),
                )
        else:
            logger.error("Network error: %s", e)
            if root and root.winfo_exists():
                # FIX: capture e as default argument so it's available in lambda
                root.after(
                    0,
                    lambda err=e: (
                        status_label.config(
                            text=f"Network error: {err}",
                            foreground="red",
                        ),
                        start_btn.config(state="normal"),
                    ),
                )
    except Exception as e:
        logger.error("Unexpected server error: %s", e)
        if root and root.winfo_exists():
            root.after(
                0,
                lambda err=e: (
                    status_label.config(text=f"Error: {err}", foreground="red"),
                    start_btn.config(state="normal"),
                ),
            )
    finally:
        server_running = False
        if httpd:
            try:
                httpd.server_close()
            except Exception:
                pass


def stop_server():
    global httpd, server_running, server_thread
    if not server_running:
        return
    logger.info("Stopping server...")
    stop_flag.set()
    try:
        socket.create_connection(("127.0.0.1", int(port_var.get())), timeout=1).close()
    except Exception:
        pass
    if server_thread and server_thread.is_alive():
        server_thread.join(timeout=2)
    server_running = False
    httpd = None
    if root and root.winfo_exists():
        root.after(
            0,
            lambda: (
                status_label.config(text="Server stopped", foreground="#e67e22"),
                start_btn.config(state="normal"),
                stop_btn.config(state="disabled"),
                root.after(
                    2000,
                    lambda: status_label.config(
                        text="Ready", foreground="#27ae60"
                    ),
                ),
            ),
        )


def remove_certificates():
    try:
        cert_file = (
            cert_file_var.get().strip()
            if "cert_file_var" in globals()
            else HTTPS_CONFIG["CERT_FILE_DEFAULT"]
        )
        key_file = (
            key_file_var.get().strip()
            if "key_file_var" in globals()
            else HTTPS_CONFIG["KEY_FILE_DEFAULT"]
        )

        for path in (cert_file, key_file):
            if path and os.path.exists(path):
                try:
                    os.remove(path)
                    logger.info("Removed certificate-related file: %s", path)
                except Exception as e:
                    logger.warning("Could not remove file %s: %s", path, e)
    except Exception as e:
        logger.warning("Error during certificate cleanup: %s", e)


def remove_log_file():
    try:
        if LOG_FILE and os.path.exists(LOG_FILE):
            os.remove(LOG_FILE)
            print(f"Removed log file: {LOG_FILE}")
    except Exception as e:
        print(f"Could not remove log file {LOG_FILE}: {e}")


def cleanup():
    global cleanup_done
    if cleanup_done:
        return
    cleanup_done = True
    stop_server()
    remove_certificates()
    remove_log_file()


def on_closing():
    cleanup()
    try:
        root.destroy()
    except Exception:
        pass


def browse_folder():
    folder = filedialog.askdirectory()
    if folder:
        folder_var.set(folder)


def copy_to_clipboard():
    text = status_label.cget("text")
    match = re.search(r"https?://[^\s]+", text)
    if match:
        pyperclip.copy(match.group())
        old = status_label.cget("text")
        status_label.config(text="✓ URL copied!", foreground="#2980b9")
        root.after(
            1500, lambda: status_label.config(text=old, foreground="#27ae60")
        )


def toggle_upload_fields():
    max_upload_entry.config(
        state="normal" if upload_enabled_var.get() else "disabled"
    )


def toggle_auth_fields():
    state = "normal" if auth_enabled_var.get() else "disabled"
    username_entry.config(state=state)
    password_entry.config(state=state)
    if auth_enabled_var.get():
        if not username_var.get():
            username_var.set("admin")
        if not password_var.get():
            password_var.set("admin")
    else:
        username_var.set("")
        password_var.set("")


def toggle_https_fields():
    state = "normal" if https_enabled_var.get() else "disabled"
    cert_entry.config(state=state)
    key_entry.config(state=state)
    gen_cert_btn.config(state=state)


def generate_cert_from_gui():
    if not CRYPTOGRAPHY_AVAILABLE:
        messagebox.showerror(
            "Certificate error",
            "The 'cryptography' package is required to generate certificates.\n\n"
            "Install it with:\n\npip install cryptography",
        )
        return

    cert_file = (
        cert_file_var.get().strip() or HTTPS_CONFIG["CERT_FILE_DEFAULT"]
    )
    key_file = key_file_var.get().strip() or HTTPS_CONFIG["KEY_FILE_DEFAULT"]
    cert_file_var.set(cert_file)
    key_file_var.set(key_file)

    ok = generate_self_signed_cert_python(cert_file, key_file)
    if ok:
        messagebox.showinfo(
            "Certificate",
            f"Self-signed certificate generated:\n\nCert: {cert_file}\nKey:  {key_file}\n\n"
            "Your browser will show a warning when first visiting this HTTPS URL.",
        )
    else:
        messagebox.showerror(
            "Certificate error",
            "Could not generate certificate automatically using Python.\n\n"
            "Check logs for details.",
        )


def validate_inputs():
    if not folder_var.get() or not os.path.isdir(folder_var.get()):
        messagebox.showerror("Error", "Please select a valid folder")
        return False
    try:
        p = int(port_var.get())
        if not (1 <= p <= 65535):
            raise ValueError
    except Exception:
        messagebox.showerror("Error", "Invalid port (1-65535)")
        return False
    if auth_enabled_var.get() and (
        not username_var.get().strip() or not password_var.get().strip()
    ):
        messagebox.showerror("Error", "Username and password required")
        return False
    if https_enabled_var.get():
        cert_file = cert_file_var.get().strip()
        key_file = key_file_var.get().strip()
        if not cert_file or not key_file:
            messagebox.showerror(
                "Error",
                "HTTPS is enabled. Please provide certificate and key file paths or generate them.",
            )
            return False
    return True


def run_server():
    global server_thread
    if server_running:
        status_label.config(
            text="Server is already running!", foreground="#e67e22"
        )
        root.after(
            2000,
            lambda: status_label.config(
                text="Ready", foreground="#27ae60"
            ),
        )
        return
    if not validate_inputs():
        return
    stop_flag.clear()

    enable_https = https_enabled_var.get()
    cert_file = cert_file_var.get().strip() or None
    key_file = key_file_var.get().strip() or None

    server_thread = threading.Thread(
        target=start_server,
        args=(
            folder_var.get(),
            int(port_var.get()),
            username_var.get().strip() or None,
            password_var.get().strip() or None,
            upload_enabled_var.get(),
            int(max_upload_var.get()),
            enable_https,
            cert_file,
            key_file,
        ),
        daemon=True,
    )
    server_thread.start()
    start_btn.config(state="disabled")
    stop_btn.config(state="disabled")
    status_label.config(text="Starting server...", foreground="#e67e22")
    root.after(500, check_server_started)


def check_server_started():
    if server_running:
        auth = " 🔒 Protected" if auth_enabled_var.get() else ""
        up = (
            f" | 📤 Max {max_upload_var.get()}MB"
            if upload_enabled_var.get()
            else " | 📤 Off"
        )
        scheme = "https" if https_enabled_var.get() else "http"
        # Use LAN IP so other machines can connect (especially for HTTPS)
        url = (
            f"Server running on {scheme}://{get_lan_ip()}:{port_var.get()}"
            f"{auth}{up}"
        )
        status_label.config(text=url, foreground="#27ae60")
        stop_btn.config(state="normal")
    else:
        root.after(500, check_server_started)


def get_lan_ip():
    """
    Try to get a LAN-reachable IP instead of 127.0.0.1,
    so that the printed URL works from other machines on the same network.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Doesn't need to be reachable; just used to pick the right interface
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        # Fallback to localhost
        return "127.0.0.1"
    finally:
        s.close()


def set_default_folder():
    try:
        docs = str(Path.home() / "Documents")
        folder_var.set(docs if os.path.isdir(docs) else str(Path.home()))
    except Exception:
        folder_var.set(os.getcwd())


# --- Log window management ---
log_window = None
log_text_widget = None


def get_log_text_widget():
    global log_text_widget
    return log_text_widget


def show_log_window():
    global log_window, log_text_widget
    if log_window and log_window.winfo_exists():
        log_window.lift()
        return

    log_window = Toplevel(root)
    log_window.title("Activity log")
    log_window.geometry("780x320")

    frame = Frame(log_window, padx=8, pady=8)
    frame.pack(fill="both", expand=True)
    frame.columnconfigure(0, weight=1)
    frame.rowconfigure(0, weight=1)

    log_text = Text(
        frame,
        wrap="word",
        state="disabled",
        font=("Consolas", 9),
        bg="#f8f9fb",
    )
    log_text.grid(row=0, column=0, sticky="nsew")
    scroll = ttk.Scrollbar(frame, orient="vertical", command=log_text.yview)
    scroll.grid(row=0, column=1, sticky="ns")
    log_text.configure(yscrollcommand=scroll.set)

    log_text_widget = log_text

    def on_close():
        try:
            log_window.destroy()
        except Exception:
            pass

    log_window.protocol("WM_DELETE_WINDOW", on_close)


# Ensure cleanup is called on interpreter exit as a backup
atexit.register(cleanup)

# === GUI (compact, improved) ===
root = Tk()
root.title(APP_NAME)
root.resizable(False, False)

style = ttk.Style()
try:
    style.theme_use("clam")
except Exception:
    pass
style.configure("TLabel", padding=2)
style.configure("TButton", padding=3)
style.configure("TLabelframe", padding=8)
style.configure("TLabelframe.Label", font=("Segoe UI", 9, "bold"))

main = Frame(root, padx=14, pady=14)
main.pack(fill="both", expand=True)

# Variables
folder_var = StringVar()
port_var = StringVar(value="8000")
auth_enabled_var = BooleanVar()
username_var = StringVar()
password_var = StringVar()
upload_enabled_var = BooleanVar(value=True)
max_upload_var = StringVar(value="1000")
https_enabled_var = BooleanVar(value=HTTPS_CONFIG["ENABLE_HTTPS_DEFAULT"])
cert_file_var = StringVar(value=HTTPS_CONFIG["CERT_FILE_DEFAULT"])
key_file_var = StringVar(value=HTTPS_CONFIG["KEY_FILE_DEFAULT"])

set_default_folder()

# Top: Name / credits with clickable GitHub / LinkedIn text
Label(
    main,
    text=APP_NAME,
    font=("Segoe UI", 11, "bold"),
).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 4))

credit_frame = Frame(main)
credit_frame.grid(row=1, column=0, columnspan=3, sticky="w", pady=(0, 8))

Label(
    credit_frame,
    text=APP_AUTHOR + " |",
    font=("Segoe UI", 8),
).grid(row=0, column=0, sticky="w")


def open_github():
    webbrowser.open(APP_GITHUB_URL)


def open_linkedin():
    webbrowser.open(APP_LINKEDIN_URL)


github_label = Label(
    credit_frame,
    text=" GitHub ",
    font=("Segoe UI", 8, "underline"),
    fg="#2980b9",
    cursor="hand2",
)
github_label.grid(row=0, column=1, sticky="w")
github_label.bind("<Button-1>", lambda e: open_github())

Label(
    credit_frame,
    text="|",
    font=("Segoe UI", 8),
).grid(row=0, column=2, sticky="w")

linkedin_label = Label(
    credit_frame,
    text=" LinkedIn",
    font=("Segoe UI", 8, "underline"),
    fg="#2980b9",
    cursor="hand2",
)
linkedin_label.grid(row=0, column=3, sticky="w")
linkedin_label.bind("<Button-1>", lambda e: open_linkedin())

# Row 2: Folder + Port
Label(main, text="Folder:", font=("Segoe UI", 9, "bold")).grid(
    row=2, column=0, sticky="w"
)
folder_entry = ttk.Entry(main, textvariable=folder_var, width=38)
folder_entry.grid(row=2, column=1, sticky="ew", padx=(6, 4))
ttk.Button(main, text="Browse…", command=browse_folder).grid(
    row=2, column=2, padx=(0, 0)
)

Label(main, text="Port:", font=("Segoe UI", 9, "bold")).grid(
    row=3, column=0, sticky="w", pady=(8, 0)
)
ttk.Entry(main, textvariable=port_var, width=10).grid(
    row=3, column=1, sticky="w", padx=(6, 0), pady=(8, 0)
)

main.columnconfigure(1, weight=1)

# Row 4: Auth + HTTPS
options_frame = Frame(main)
options_frame.grid(row=4, column=0, columnspan=3, sticky="ew", pady=(10, 0))
options_frame.columnconfigure(0, weight=1)
options_frame.columnconfigure(1, weight=1)

auth_frame = ttk.LabelFrame(options_frame, text=" Authentication ")
auth_frame.grid(row=0, column=0, sticky="ew", padx=(0, 6))
auth_frame.columnconfigure(1, weight=1)

Checkbutton(
    auth_frame,
    text="Enable Basic Auth",
    variable=auth_enabled_var,
    command=toggle_auth_fields,
).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 4))

Label(auth_frame, text="Username:").grid(row=1, column=0, sticky="w")
username_entry = ttk.Entry(auth_frame, textvariable=username_var)
username_entry.grid(row=1, column=1, sticky="ew", padx=(4, 0))

Label(auth_frame, text="Password:").grid(
    row=2, column=0, sticky="w", pady=(4, 0)
)
password_entry = ttk.Entry(auth_frame, textvariable=password_var, show="●")
password_entry.grid(
    row=2, column=1, sticky="ew", padx=(4, 0), pady=(4, 0)
)

https_frame = ttk.LabelFrame(options_frame, text=" HTTPS / TLS ")
https_frame.grid(row=0, column=1, sticky="ew", padx=(6, 0))
https_frame.columnconfigure(1, weight=1)

Checkbutton(
    https_frame,
    text="Enable HTTPS",
    variable=https_enabled_var,
    command=toggle_https_fields,
).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 4))

Label(https_frame, text="Cert file:").grid(row=1, column=0, sticky="w")
cert_entry = ttk.Entry(https_frame, textvariable=cert_file_var)
cert_entry.grid(row=1, column=1, sticky="ew", padx=(4, 0))

Label(https_frame, text="Key file:").grid(
    row=2, column=0, sticky="w", pady=(4, 0)
)
key_entry = ttk.Entry(https_frame, textvariable=key_file_var)
key_entry.grid(
    row=2, column=1, sticky="ew", padx=(4, 0), pady=(4, 0)
)

gen_cert_btn = ttk.Button(
    https_frame,
    text="Generate self-signed cert",
    command=generate_cert_from_gui,
)
gen_cert_btn.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(6, 0))

# Row 5: Upload settings
upload_frame = ttk.LabelFrame(main, text=" File Upload ")
upload_frame.grid(
    row=5, column=0, columnspan=3, sticky="ew", pady=(10, 0)
)
upload_frame.columnconfigure(1, weight=1)

Checkbutton(
    upload_frame,
    text="Enable File Upload",
    variable=upload_enabled_var,
    command=toggle_upload_fields,
).grid(row=0, column=0, columnspan=2, sticky="w")

Label(upload_frame, text="Max size (MB):").grid(
    row=1, column=0, sticky="w", pady=(4, 0)
)
max_upload_entry = ttk.Entry(upload_frame, textvariable=max_upload_var, width=10)
max_upload_entry.grid(
    row=1, column=1, sticky="w", padx=(4, 0), pady=(4, 0)
)

toggle_auth_fields()
toggle_upload_fields()
toggle_https_fields()

# Row 6: Buttons and 'View log'
btn_frame = Frame(main)
btn_frame.grid(row=6, column=0, columnspan=3, sticky="ew", pady=(12, 0))
btn_frame.columnconfigure(0, weight=1)
btn_frame.columnconfigure(1, weight=1)
btn_frame.columnconfigure(2, weight=0)

start_btn = ttk.Button(btn_frame, text="▶ Start server", command=run_server)
start_btn.grid(row=0, column=0, sticky="ew", padx=(0, 4))

stop_btn = ttk.Button(
    btn_frame, text="⏹ Stop server", command=stop_server, state="disabled"
)
stop_btn.grid(row=0, column=1, sticky="ew", padx=(4, 4))

log_btn = ttk.Button(btn_frame, text="📜 View log", command=show_log_window)
log_btn.grid(row=0, column=2, sticky="e")

# Row 7: Status
status_label = Label(
    main,
    text="Ready",
    font=("Segoe UI", 9, "bold"),
    fg="#27ae60",
    cursor="hand2",
    anchor="w",
)
status_label.grid(row=7, column=0, columnspan=3, sticky="ew", pady=(10, 0))
status_label.bind("<Button-1>", lambda e: copy_to_clipboard())

# Attach TkTextHandler AFTER root and log_window functions exist
text_handler = TkTextHandler(get_log_text_widget)
text_handler.setFormatter(
    logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
)
logger.addHandler(text_handler)

root.protocol("WM_DELETE_WINDOW", on_closing)
root.mainloop()