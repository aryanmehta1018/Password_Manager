from flask import Flask, request, redirect, render_template, flash, url_for, jsonify, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from argon2 import PasswordHasher
import secrets
import pyotp
import os
import re
import requests
from cryptography.fernet import Fernet
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from collections import Counter
# Email OTP imports
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta

from sqlalchemy import func  
import json
from werkzeug.utils import secure_filename

from webauthn import (
    generate_registration_options,
    generate_authentication_options,
    verify_registration_response,
    verify_authentication_response,
)

from webauthn.helpers import options_to_json

from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    UserVerificationRequirement,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialType
)

import json
import base64


WEBAUTHN_RP_ID = "localhost"  # change to domain in production
WEBAUTHN_RP_NAME = "Secure Password Manager"
WEBAUTHN_ORIGIN = "http://localhost:5000"


# ===========================
# Password Encryption
# ===========================
MASTER_KEY = Fernet(b"KwgUdkldOt9n4-mXvsI0OIkN6PopNeRSSTTfYhuZegQ=")

def encrypt_password(plain):
    return MASTER_KEY.encrypt(plain.encode()).decode()

def decrypt_password(cipher):
    return MASTER_KEY.decrypt(cipher.encode()).decode()

def ip_to_location(ip):
    if not ip:
        return "Unknown"

    # Private/local IP ranges
    local_ranges = (
        "127.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
        "172.2", "172.30.", "172.31.", "192.168.", "::1"
    )

    if ip.startswith(local_ranges):
        return "Local Machine"

    try:
        url = f"http://ip-api.com/json/{ip}?fields=city,regionName,country,status"
        r = requests.get(url, timeout=2).json()

        if r.get("status") != "success":
            return "Unknown"

        city = r.get("city")
        region = r.get("regionName")
        country = r.get("country")

        return ", ".join([v for v in [city, region, country] if v])
    except:
        return "Unknown"

# ===========================
# Basic App Setup
# ===========================
ph = PasswordHasher()
app = Flask(__name__)
CORS(app, supports_credentials=True)

app.config['SECRET_KEY'] = os.environ.get("FLASK_SECRET", "change_in_production")
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:ronaldorox@localhost/new'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = None
login_manager.login_message_category = None


# ===========================
# Gmail SMTP OTP Sender
# ===========================
def generate_recovery_codes():
        return [secrets.token_hex(4) for _ in range(8)]

def send_login_otp(email, otp):
    sender = "aryanmehta45321@gmail.com"
    app_password = "cxet vuuq oqwm kzcd"

    ctx = get_login_context()

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Your Secure Login Code"
    msg["From"] = f"Secure Password Manager <{sender}>"
    msg["To"] = email

    # ---------- Plain Text (Fallback) ----------
    text = f"""
Your One-Time Password (OTP): {otp}

Login Details:
IP Address: {ctx['ip']}
Location: {ctx['location']}
Device: {ctx['user_agent']}

This code expires in 5 minutes.

If this wasn’t you, secure your account immediately.
"""

    # ---------- HTML Email ----------
    html = f"""
<!DOCTYPE html>
<html>
<head>
<meta name="color-scheme" content="light dark">
<meta name="supported-color-schemes" content="light dark">
<style>
  body {{
    margin: 0;
    padding: 0;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial;
    background-color: #f4f6f8;
  }}

  .container {{
    max-width: 460px;
    margin: 30px auto;
    background: #ffffff;
    border-radius: 12px;
    padding: 28px;
    box-shadow: 0 12px 30px rgba(0,0,0,0.12);
  }}

  h1 {{
    font-size: 20px;
    text-align: center;
    margin-bottom: 10px;
    color: #1f2937;
  }}

  .otp {{
    font-size: 34px;
    font-weight: 700;
    letter-spacing: 6px;
    text-align: center;
    color: #2563eb;
    margin: 24px 0;
  }}

  .text {{
    text-align: center;
    font-size: 14px;
    color: #4b5563;
    line-height: 1.6;
  }}

  .card {{
    background: #f9fafb;
    border-radius: 8px;
    padding: 14px;
    margin-top: 20px;
    font-size: 13px;
    color: #374151;
  }}

  .warning {{
    background: #fff1f2;
    border-left: 4px solid #ef4444;
    padding: 12px;
    margin-top: 20px;
    font-size: 13px;
    color: #7f1d1d;
  }}

  .footer {{
    font-size: 12px;
    color: #9ca3af;
    text-align: center;
    margin-top: 26px;
  }}

  @media (prefers-color-scheme: dark) {{
    body {{
      background-color: #0f172a;
    }}
    .container {{
      background: #020617;
      color: #e5e7eb;
    }}
    .card {{
      background: #020617;
      color: #cbd5f5;
    }}
    .warning {{
      background: #3f1d1d;
      color: #fecaca;
    }}
  }}
</style>
</head>
<body>
  <div class="container">
    <h1>Secure Password Manager</h1>

    <div class="text">
      Use the verification code below to complete your login.
    </div>

    <div class="otp">{otp}</div>

    <div class="text">
      This code expires in <strong>5 minutes</strong>.
    </div>

    <div class="card">
      <strong>Login Details</strong><br><br>
      📍 <strong>Location:</strong> {ctx['location']}<br>
      🌐 <strong>IP Address:</strong> {ctx['ip']}<br>
      💻 <strong>Device:</strong> {ctx['user_agent']}
    </div>

    <div class="warning">
      ⚠️ <strong>Wasn’t you?</strong><br>
      If you didn’t attempt this login, reset your password immediately and secure your account.
    </div>

    <div class="footer">
      Never share your OTP with anyone.<br>
      © Secure Password Manager
    </div>
  </div>
</body>
</html>
"""

    msg.attach(MIMEText(text, "plain"))
    msg.attach(MIMEText(html, "html"))

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(sender, app_password)
            smtp.send_message(msg)
        return True
    except Exception as e:
        print("Email sending error:", e)
        return False
    
def send_password_reset_email(user):
    sender = "aryanmehta45321@gmail.com"
    app_password = "cxet vuuq oqwm kzcd"

    token = generate_reset_token(user)
    reset_link = url_for("reset_password", token=token, _external=True)

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Reset Your Password"
    msg["From"] = f"Secure Password Manager <{sender}>"
    msg["To"] = user.email

    # ---------- Plain Text ----------
    text = f"""
We received a request to reset your password.

Reset Link:
{reset_link}

This link expires in 30 minutes.

If you didn’t request this, you can safely ignore this email.
"""

    # ---------- HTML ----------
    html = f"""
<!DOCTYPE html>
<html>
<head>
<meta name="color-scheme" content="light dark">
<style>
body {{
  font-family: -apple-system, BlinkMacSystemFont, Segoe UI, Roboto;
  background: #f4f6f8;
}}
.container {{
  max-width: 460px;
  margin: 30px auto;
  background: #ffffff;
  border-radius: 12px;
  padding: 28px;
}}
.button {{
  display: block;
  width: 100%;
  padding: 14px;
  background: #dc2626;
  color: #ffffff;
  text-align: center;
  border-radius: 8px;
  text-decoration: none;
  font-weight: 600;
  margin: 24px 0;
}}
.card {{
  background: #f9fafb;
  padding: 14px;
  border-radius: 8px;
  font-size: 13px;
}}
.footer {{
  font-size: 12px;
  text-align: center;
  color: #9ca3af;
  margin-top: 22px;
}}
@media (prefers-color-scheme: dark) {{
  body {{ background: #020617; }}
  .container {{ background: #020617; color: #e5e7eb; }}
  .card {{ background: #020617; }}
}}
</style>
</head>
<body>
<div class="container">
  <h2>Password Reset Request</h2>
  <p>We received a request to reset your password.</p>

  <a href="{reset_link}" class="button">Reset Password</a>

  <div class="card">
    ⏳ This link expires in <strong>30 minutes</strong><br>
    🔐 One-time use only
  </div>

  <p>If you didn’t request this, you can safely ignore this email.</p>

  <div class="footer">
    Secure Password Manager
  </div>
</div>
</body>
</html>
"""

    msg.attach(MIMEText(text, "plain"))
    msg.attach(MIMEText(html, "html"))

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(sender, app_password)
            smtp.send_message(msg)
        return True
    except Exception as e:
        print("Password reset email error:", e)
        return False

def verify_recovery_code(user, submitted_code):
    if not user.recovery_codes:
        return False

    codes = json.loads(user.recovery_codes)

    for stored_hash in codes:
        try:
            if ph.verify(stored_hash, submitted_code):
                # remove used code (one-time)
                codes.remove(stored_hash)
                user.recovery_codes = json.dumps(codes)
                db.session.commit()
                return True
        except:
            continue

    return False

# ===========================
# Models
# ===========================
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    api_token = db.Column(db.String(64), unique=True, nullable=True)

    # MFA (Google Authenticator)
    mfa_enabled = db.Column(db.Boolean, default=False, nullable=False)
    mfa_secret = db.Column(db.String(64), nullable=True)

    # Email OTP fields
    otp_code = db.Column(db.String(6), nullable=True)
    otp_expiry = db.Column(db.DateTime, nullable=True)
    display_name = db.Column(db.String(100), nullable=True)
    pref_dark_mode = db.Column(db.Boolean, default=False)
    phone = db.Column(db.String(20), nullable=True)
    reset_token = db.Column(db.String(128), nullable=True)
    reset_token_expiry = db.Column(db.DateTime, nullable=True)
    recovery_codes = db.Column(db.Text, nullable=True)
    webauthn_enabled = db.Column(db.Boolean, default=False)



    def set_password(self, password):
        self.password_hash = ph.hash(password)

    def check_password(self, password):
        try:
            return ph.verify(self.password_hash, password)
        except:
            return False

    def ensure_api_token(self):
        if not self.api_token:
            self.api_token = secrets.token_hex(32)
            db.session.commit()
        return self.api_token

    def generate_api_token(self):
        self.api_token = secrets.token_hex(32)
        db.session.commit()
        return self.api_token
    


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class WebAuthnCredential(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    credential_id = db.Column(db.LargeBinary, nullable=False)
    public_key = db.Column(db.LargeBinary, nullable=False)
    sign_count = db.Column(db.Integer, default=0)

    transports = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship(
        "User",
        backref=db.backref("webauthn_credentials", lazy=True)
    )

class Passwords(db.Model):
    __tablename__ = "passwords"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    website = db.Column(db.String(255), nullable=False)
    username = db.Column(db.String(255), nullable=False)

    # 🔐 encrypted password
    password = db.Column(db.Text, nullable=False)

    # 🗂️ vault features
    category = db.Column(db.String(100), default="General")
    notes = db.Column(db.Text, nullable=True)

    # ⏱️ timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow
    )

    user = db.relationship(
        "User",
        backref=db.backref("passwords", lazy=True)
    )


class LoginActivity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(300), nullable=True)
    action = db.Column(db.String(100), nullable=False)  # e.g. "login_success", "otp_failed"
    meta = db.Column(db.Text, nullable=True)  # JSON string for extra data
    location = db.Column(db.String(255), nullable=True)
    user = db.relationship("User", backref=db.backref("activities", lazy=True))

class SessionRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    session_token = db.Column(db.String(128), nullable=False, unique=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_active = db.Column(db.DateTime, default=datetime.utcnow)
    ip = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(300), nullable=True)

    user = db.relationship("User", backref=db.backref("sessions", lazy=True))

if not hasattr(User, "display_name"):
    User.display_name = db.Column(db.String(150), nullable=True)
    User.avatar_url = db.Column(db.String(500), nullable=True)
    User.pref_dark_mode = db.Column(db.Boolean, default=False, nullable=False)

# ---------- Helper: log activity ----------
def log_activity(user_id, action, ip=None, meta=None):
    from datetime import datetime

    if ip is None:
        ip = get_real_ip()

    # Convert localhost into user-friendly label
    if ip in ("127.0.0.1", "::1"):
        location = "Local Machine"
    else:
        location = ip_to_location(ip)

    entry = LoginActivity(
        user_id=user_id,
        ip=ip,
        user_agent=request.headers.get("User-Agent")[:200],
        action=action,
        location=location,
        timestamp=datetime.utcnow()
    )

    db.session.add(entry)
    db.session.commit()

def generate_reset_token(user):
    token = secrets.token_urlsafe(48)
    user.reset_token = token
    user.reset_token_expiry = datetime.utcnow() + timedelta(minutes=30)
    db.session.commit()
    return token


# ---------- Helper: password health and security score ----------

def password_strength_score(plain):
    """Return 0-100 password strength estimate."""
    if not plain: return 0
    score = 0
    length = len(plain)
    # length contribution
    score += min(40, (length * 4))  # up to 40
    classes = 0
    if re.search(r'[a-z]', plain): classes += 1
    if re.search(r'[A-Z]', plain): classes += 1
    if re.search(r'\d', plain): classes += 1
    if re.search(r'[^A-Za-z0-9]', plain): classes += 1
    score += int((classes / 4) * 35)  # up to 35
    if length > 12:
        score += min(10, length - 12)
    # penalties
    low = plain.lower()
    commons = {"123456","password","qwerty","abc123","111111","123123"}
    if low in commons:
        score -= 40
    if re.fullmatch(r'(.)\1{4,}', plain):
        score -= 30
    score = max(0, min(100, score))
    return int(score)

def analyze_user_passwords(user):
    """
    Returns a dict:
      {
        total: int,
        weak: int,
        reused_groups: [{"password": "****", "count": 2, "sites": [...]}, ...],
        oldest_ids: [password_id,...],
        individual: [ {id, website, username, score, last_changed?}, ... ]
      }
    """
    pw_objs = user.passwords
    result = {"total": len(pw_objs), "weak": 0, "reused_groups": [], "individual": []}
    # decrypt and compute
    seen = {}
    for p in pw_objs:
        try:
            plain = decrypt_password(p.password)
        except Exception:
            plain = None
        score = password_strength_score(plain or "")
        if score < 50:
            result["weak"] += 1
        result["individual"].append({
            "id": p.id,
            "website": p.website,
            "username": p.username,
            "score": score
        })
        if plain:
            seen.setdefault(plain, []).append(p)
    # reused
    for plain, entries in seen.items():
        if len(entries) > 1:
            result["reused_groups"].append({
                "count": len(entries),
                "sites": [e.website for e in entries],
                "password_example_masked": (plain[:2] + "***" + plain[-1:]) if len(plain) > 3 else "***"
            })
    return result

def compute_security_score(user):
    """
    Aggregate a 0-100 security score from multiple signals.
    """
    base = 100
    pw_analysis = analyze_user_passwords(user)
    # penalty weak passwords
    base -= pw_analysis["weak"] * 6
    # penalty reused
    for g in pw_analysis["reused_groups"]:
        base -= (g["count"] - 1) * 8
    # penalty: no MFA
    if not user.mfa_enabled:
        base -= 10
    # penalty: no email-otp set (we use otp fields as sign)
    if not user.otp_code and user.otp_expiry is None:
        # we won't penalize too harshly because otp used only at login
        base -= 3
    # penalty: no api token
    if not user.api_token:
        base -= 3
    # clamp
    base = max(0, min(100, base))
    return int(base)

with app.app_context():
    db.create_all()

def get_real_ip():
    # If you're behind reverse proxy / local dev tools
    if request.headers.get("X-Forwarded-For"):
        return request.headers.get("X-Forwarded-For").split(",")[0].strip()

    ip = request.remote_addr
    if ip in (None, "127.0.0.1", "::1"):
        return "127.0.0.1"  # We will map this to Local Machine later

    return ip

def get_login_context():
    ip = get_real_ip()
    user_agent = request.headers.get("User-Agent", "Unknown")

    if ip in ("127.0.0.1", "::1"):
        location = "Local Machine"
    else:
        location = ip_to_location(ip)

    return {
        "ip": ip,
        "location": location,
        "user_agent": user_agent[:120]
    }


def get_geo_from_ip(ip):
    """Returns city, region, country from IP using free IP API."""
    try:
        if ip in ("127.0.0.1", "localhost"):
            return "Localhost"

        url = f"http://ip-api.com/json/{ip}"
        res = requests.get(url, timeout=2).json()

        if res.get("status") == "success":
            city = res.get("city")
            region = res.get("regionName")
            country = res.get("country")

            location_parts = [p for p in [city, region, country] if p]
            return ", ".join(location_parts)

        return "Unknown"
    except:
        return "Unknown"


@app.before_request
def update_session_last_active():
    if current_user.is_authenticated:
        token = session.get("session_token")
        if token:
            s = SessionRecord.query.filter_by(session_token=token).first()
            if s:
                s.last_active = datetime.utcnow()
                db.session.commit()


# ===========================
# Routes
# ===========================
@app.route('/')
def home():
    return """
    <div style='text-align:center;margin-top:50px;font-size:24px;'>
        <p>Welcome to the Password Manager!</p>
        <p><a href='/login'>Click Here To Login</a></p>
    </div>
    """


# ---------------------------
# Registration
# ---------------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        if User.query.filter_by(email=email).first():
            flash("Email already exists", "danger")
            return redirect(url_for("register"))

        user = User(email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash("Registration successful! Login now.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


# ---------------------------
# LOGIN (Password → Email OTP → MFA → Dashboard)
# ---------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get("email")
        password = request.form.get("password")

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):

            otp = str(secrets.randbelow(1000000)).zfill(6)
            user.otp_code = otp
            user.otp_expiry = datetime.utcnow() + timedelta(minutes=5)
            db.session.commit()

            send_login_otp(user.email, otp)

            session["pending_email_otp_user"] = user.id
            return redirect("/email_verify")

        flash("Invalid email or password", "danger")

    return render_template("login.html")



# ---------------------------
# Email OTP Verification
# ---------------------------
@app.route('/email_verify', methods=['GET', 'POST'])
def email_verify():
    user_id = session.get("pending_email_otp_user")
    if not user_id:
        return redirect("/login")

    user = User.query.get(user_id)

    if request.method == "POST":
        code = request.form.get("otp") or request.form.get("otp1")

        if not code:
            flash("Please enter the OTP.", "danger")
            return render_template("email_verify.html")

        if not user.otp_expiry or datetime.utcnow() > user.otp_expiry:
            flash("OTP expired. Please login again.", "danger")
            return redirect(url_for("login"))

        if code == user.otp_code:
            # ✅ Clear OTP
            user.otp_code = None
            user.otp_expiry = None
            db.session.commit()

            # ✅ CLEAN SESSION TRANSITION
            session.pop("pending_mfa_user", None)

            # 🔥 IF MFA ENABLED → MFA STEP
            if user.mfa_enabled or user.webauthn_enabled:
                session["pending_mfa_user"] = user.id
                return redirect(url_for("mfa_verify"))


            # 🔥 ELSE → LOGIN COMPLETE
            login_user(user)

            log_activity(
                user.id,
                "login_success",
                ip=request.remote_addr,
                meta={"method": "email_otp"}
            )

            session_token = secrets.token_hex(32)
            record = SessionRecord(
                user_id=user.id,
                session_token=session_token,
                ip=request.remote_addr,
                user_agent=request.headers.get("User-Agent")
            )
            db.session.add(record)
            db.session.commit()

            session["session_token"] = session_token

            flash("Login successful!", "success")
            return redirect(url_for("dashboard"))

        flash("Invalid OTP. Try again.", "danger")

    return render_template("email_verify.html")


@app.route('/resend_otp', methods=['POST'])
def resend_otp():
    user_id = session.get("pending_email_otp_user")
    if not user_id:
        return jsonify({"success": False, "message": "No pending login"}), 400

    user = User.query.get(user_id)

    otp = str(secrets.randbelow(1000000)).zfill(6)
    user.otp_code = otp
    user.otp_expiry = datetime.utcnow() + timedelta(minutes=5)
    db.session.commit()

    ok = send_login_otp(user.email, otp)

    if not ok:
        return jsonify({"success": False, "message": "Failed to send email"}), 500

    return jsonify({"success": True})

@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email")
        user = User.query.filter_by(email=email).first()

        # Always show success (anti-enumeration)
        if user:
            send_password_reset_email(user)
            log_activity(user.id, "password_reset_requested")

        flash("If the email exists, a reset link has been sent.", "info")
        return redirect("/login")

    return render_template("forgot_password.html")

@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()

    if not user or user.reset_token_expiry < datetime.utcnow():
        flash("Reset link is invalid or expired.", "danger")
        return redirect("/forgot_password")

    if request.method == "POST":
        password = request.form.get("password")
        confirm = request.form.get("confirm_password")

        if password != confirm:
            flash("Passwords do not match.", "danger")
            return render_template("reset_password.html", token=token)

        if len(password) < 8:
            flash("Password must be at least 8 characters.", "danger")
            return render_template("reset_password.html", token=token)

        user.set_password(password)
        user.reset_token = None
        user.reset_token_expiry = None
        db.session.commit()

        flash("Password updated successfully. Please login.", "success")
        return redirect("/login")

    return render_template("reset_password.html", token=token)



# ---------------------------
# Google Authenticator MFA
# ---------------------------

@app.route("/mfa_setup")
@login_required
def mfa_setup():
    import qrcode, base64
    from io import BytesIO

    if not current_user.mfa_secret:
        current_user.mfa_secret = pyotp.random_base32()
        db.session.commit()

    totp = pyotp.TOTP(current_user.mfa_secret)

    otp_uri = totp.provisioning_uri(
        name=current_user.email,
        issuer_name="SecurePasswordManager"
    )

    img = qrcode.make(otp_uri)
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    qr_base64 = base64.b64encode(buffer.getvalue()).decode()

    return render_template(
        "mfa_setup.html",
        qr_code=f"data:image/png;base64,{qr_base64}"
    )

@app.route("/mfa_setup/confirm", methods=["POST"])
@login_required
def mfa_setup_confirm():
    code = request.form.get("code")
    totp = pyotp.TOTP(current_user.mfa_secret)

    if not totp.verify(code):
        flash("Invalid MFA code", "danger")
        return redirect("/mfa_setup")

    current_user.mfa_enabled = True
    db.session.commit()

    log_activity(current_user.id, "mfa_enabled")

    flash("MFA enabled successfully", "success")
    return redirect("/dashboard")



@app.route("/mfa_verify", methods=["GET", "POST"])
def mfa_verify():
    user_id = session.get("pending_mfa_user")
    if not user_id:
        return redirect("/login")

    user = User.query.get(user_id)
    totp = pyotp.TOTP(user.mfa_secret)

    if request.method == "POST":
        code = (request.form.get("code") or "").strip()
        recovery_code = (request.form.get("recovery_code") or "").strip()

        # ❌ BOTH PROVIDED
        if code and recovery_code:
            flash("Use either Authenticator code OR Recovery code, not both.", "danger")
            return render_template("mfa_verify.html")

        # ❌ NONE PROVIDED
        if not code and not recovery_code:
            flash("Please enter a verification code.", "danger")
            return render_template("mfa_verify.html")

        verified = False
        method_used = None

        

        # ✅ AUTHENTICATOR
        if code:
            if not user.mfa_secret:
                flash("Authenticator is not enabled.", "danger")
                return render_template("mfa_verify.html")

            if pyotp.TOTP(user.mfa_secret).verify(code):
                verified = True
                method_used = "totp"
            else:
                flash("Invalid authenticator code.", "danger")
                return render_template("mfa_verify.html")

        # ✅ RECOVERY CODE
        if recovery_code:
            if verify_recovery_code(user, recovery_code):
                verified = True
                method_used = "recovery_code"
            else:
                flash("Invalid or already-used recovery code.", "danger")
                return render_template("mfa_verify.html")

        # ✅ LOGIN SUCCESS
        login_user(user)
        session.pop("pending_mfa_user", None)

        log_activity(
            user.id,
            "login_success",
            meta={"method": method_used}
        )

        return redirect("/dashboard")


    return render_template(
        "mfa_verify.html",
        webauthn=user.webauthn_enabled
    )


# ---------------------------
# Dashboard
# ---------------------------
@app.route('/dashboard')
@login_required
def dashboard():
    # Decrypt passwords
    vault_passwords = []
    for p in current_user.passwords:
        vault_passwords.append({
            "id": p.id,
            "website": p.website,
            "username": p.username,
            "category": p.category,
            "password_masked": "••••••••",
            "created_at": p.created_at
        })
    category_counts = Counter(
        p["category"] or "General" for p in vault_passwords
    )


    # Password analysis & security score
    pw_analysis = analyze_user_passwords(current_user)
    score = compute_security_score(current_user)

    # Activity logs
    activities = LoginActivity.query.filter_by(
        user_id=current_user.id
    ).order_by(LoginActivity.timestamp.desc()).limit(10).all()

    # Active sessions
    sessions = SessionRecord.query.filter_by(
        user_id=current_user.id
    ).order_by(SessionRecord.last_active.desc()).all()

    # Stats
    total_passwords = pw_analysis["total"]
    weak_passwords = pw_analysis["weak"]
    reused_count = len(pw_analysis["reused_groups"])

    return render_template(
        "dashboard.html",
        user=current_user,
        passwords=vault_passwords,
        score=score,
        pw_analysis=pw_analysis,
        activities=activities,
        sessions=sessions,
        total_passwords=total_passwords,
        weak_passwords=weak_passwords,
        reused_count=reused_count,
        categories=category_counts
    )

@app.route("/profile_edit", methods=["GET", "POST"])
@login_required
def profile_edit():
    if request.method == "POST":
        current_user.display_name = request.form.get("display_name")
        current_user.phone = request.form.get("phone")
        current_user.pref_dark_mode = True if request.form.get("pref_dark_mode") == "on" else False

        db.session.commit()
        flash("Profile updated!", "success")
        return redirect("/profile")

    return render_template("profile_edit.html", user=current_user)



@app.route("/profile")
@login_required
def profile():
    # password analysis & score
    pw_analysis = analyze_user_passwords(current_user)
    score = compute_security_score(current_user)

    # login activity (last 20)
    activities = LoginActivity.query.filter_by(user_id=current_user.id).order_by(LoginActivity.timestamp.desc()).limit(20).all()

    # active sessions
    sessions = SessionRecord.query.filter_by(user_id=current_user.id).order_by(SessionRecord.last_active.desc()).all()

    # other summary stats
    total_passwords = pw_analysis["total"]
    weak_passwords = pw_analysis["weak"]
    reused_count = len(pw_analysis["reused_groups"])

    return render_template(
        "profile.html",
        user=current_user,
        score=score,
        pw_analysis=pw_analysis,
        activities=activities,
        sessions=sessions,
        total_passwords=total_passwords,
        weak_passwords=weak_passwords,
        reused_count=reused_count
    )

@app.route("/profile/update", methods=["POST"])
@login_required
def profile_update():
    current_user.display_name = request.form.get("display_name")
    current_user.phone = request.form.get("phone")
    current_user.bio = request.form.get("bio")
    current_user.avatar_url = request.form.get("avatar_url")

    db.session.commit()
    flash("Profile updated successfully!", "success")
    return redirect("/profile")

@app.route("/profile/update_dark_mode", methods=["POST"])
@login_required
def update_dark_mode():
    data = request.json
    current_user.pref_dark_mode = data.get("enabled", False)
    db.session.commit()
    return jsonify(success=True)

# ---------- Small admin/action endpoints used by the UI ----------
@app.route("/profile/regenerate_token", methods=["POST"])
@login_required
def profile_regenerate_token():
    token = current_user.generate_api_token()
    log_activity(current_user.id, "regenerate_api_token", ip=request.remote_addr, user_agent=request.headers.get("User-Agent"))
    return jsonify({"success": True, "token": token})

@app.route("/profile/revoke_session", methods=["POST"])
@login_required
def profile_revoke_session():
    data = request.get_json() or {}
    sid = data.get("session_id")

    if not sid:
        return jsonify({"success": False}), 400

    s = SessionRecord.query.filter_by(
        id=sid,
        user_id=current_user.id
    ).first()

    if not s:
        return jsonify({"success": False}), 404

    # 🔥 If user revokes their CURRENT session
    if session.get("session_token") == s.session_token:
        session.clear()  # logs user out immediately

    db.session.delete(s)
    db.session.commit()

    log_activity(
        current_user.id,
        "session_revoked",
        meta={"session_id": sid}
    )

    return jsonify({"success": True})



@app.route("/profile/toggle_mfa", methods=["POST"])
@login_required
def profile_toggle_mfa():
    # toggles MFA on/off; for enabling we redirect to mfa_setup page or return url
    action = request.json.get("action")
    if action == "disable":
        current_user.mfa_enabled = False
        current_user.mfa_secret = None
        current_user.webauthn_enabled = False
        WebAuthnCredential.query.filter_by(user_id=current_user.id).delete()
        db.session.commit()
        log_activity(current_user.id, "mfa_disabled")
        return jsonify({"success": True})
    else:
        # enable -> return mfa setup URL so frontend can navigate
        return jsonify({"success": True, "setup_url": url_for("mfa_setup")})

@app.route("/profile/export", methods=["POST"])
@login_required
def profile_export():
    # export user's passwords in encrypted JSON (they can download)
    data = []
    for p in current_user.passwords:
        data.append({
            "website": p.website,
            "username": p.username,
            "password_encrypted": p.password,
            "id": p.id
        })
    payload = {"exported_at": datetime.utcnow().isoformat(), "data": data}
    # return as JSON response
    return jsonify({"success": True, "payload": payload})

@app.route("/profile/delete_account", methods=["POST"])
@login_required
def profile_delete_account():
    # require confirmation param
    confirm = (request.json or {}).get("confirm")
    if confirm != "DELETE":
        return jsonify({"success": False, "message": "missing confirmation"}), 400

    # delete user-related data (careful in production)
    # delete passwords
    Passwords.query.filter_by(user_id=current_user.id).delete()
    SessionRecord.query.filter_by(user_id=current_user.id).delete()
    LoginActivity.query.filter_by(user_id=current_user.id).delete()
    db.session.commit()

    # finally delete user
    uid = current_user.id
    logout_user()
    u = User.query.get(uid)
    db.session.delete(u)
    db.session.commit()
    return jsonify({"success": True})

@app.route("/vault/reveal/<int:pid>", methods=["POST"])
@login_required
def vault_reveal(pid):
    entry = Passwords.query.filter_by(
        id=pid,
        user_id=current_user.id
    ).first_or_404()

    decrypted = decrypt_password(entry.password)

    log_activity(
        current_user.id,
        "vault_reveal",
        meta={"website": entry.website}
    )

    return jsonify({"password": decrypted})


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


# ---------------------------
# Add Password
# ---------------------------
@app.route('/add_password', methods=['GET', 'POST'])
@login_required
def add_password():
    if request.method == 'POST':
        website = request.form.get('website')
        username = request.form.get('username')
        password = request.form.get('password')

        category = request.form.get('category', 'General')
        notes = request.form.get('notes')

        encrypted_password = encrypt_password(password)

        new_entry = Passwords(
            user_id=current_user.id,
            website=website,
            username=username,
            password=encrypted_password,
            category=category,
            notes=notes
        )

        db.session.add(new_entry)
        db.session.commit()

        log_activity(
            current_user.id,
            "vault_add",
            meta={"website": website}
        )

        flash("Password added to vault", "success")
        return redirect(url_for("dashboard"))

    return render_template("add_password.html")

@app.route("/edit_password/<int:password_id>", methods=["GET", "POST"])
@login_required
def edit_password(password_id):
    password_entry = Passwords.query.filter_by(
        id=password_id,
        user_id=current_user.id
    ).first_or_404()

    if request.method == "POST":
        password_entry.website = request.form.get("website")
        password_entry.username = request.form.get("username")
        password_entry.category = request.form.get("category")
        password_entry.notes = request.form.get("notes")

        new_password = request.form.get("password")
        if new_password:
            password_entry.password = encrypt_password(new_password)

        db.session.commit()
        log_activity(
            current_user.id,
            "password_edited",
            meta={"password_id": password_id}
        )
        flash("Password updated successfully", "success")
        return redirect("/dashboard")

    return render_template(
        "edit_password.html",
        password=password_entry
    )

# ---------------------------
# Delete Password
# ---------------------------
@app.route('/delete_password/<int:password_id>', methods=['POST'])
@login_required
def delete_password(password_id):
    entry = Passwords.query.get_or_404(password_id)

    if entry.user_id != current_user.id:
        return {"success": False, "message": "Unauthorized"}, 403

    db.session.delete(entry)
    db.session.commit()
    return {"success": True, "message": "Password deleted"}


# ==========================================
# API ROUTES (for Browser Extension)
# ==========================================
@app.route('/api/save_credentials', methods=['POST'])
def save_credentials():
    data = request.json
    token = data.get("api_token")
    website = data.get("website")
    username = data.get("username")
    password = data.get("password")

    user = User.query.filter_by(api_token=token).first()
    if not user:
        return {"success": False, "message": "Invalid token"}, 401

    existing = Passwords.query.filter_by(
        user_id=user.id,
        website=website,
        username=username
    ).first()

    if existing:
        if existing.password != password:
            return {"success": False, "update_available": True}

        return {"success": True, "message": "Already saved"}

    new_entry = Passwords(
        user_id=user.id,
        website=website,
        username=username,
        password=encrypt_password(password)
    )

    db.session.add(new_entry)
    db.session.commit()

    return {"success": True}


@app.route('/api/get_credentials', methods=['POST'])
def get_credentials():
    data = request.json
    token = data.get("api_token")
    website = data.get("website")

    user = User.query.filter_by(api_token=token).first()
    if not user:
        return {"success": False, "message": "Invalid token"}, 401

    entry = Passwords.query.filter_by(user_id=user.id, website=website).first()
    if not entry:
        return {"success": False, "message": "Not found"}, 404

    return {
        "success": True,
        "username": entry.username,
        "password": decrypt_password(entry.password)
    }

@app.route('/generate_token')
@login_required
def generate_token():
    token = current_user.ensure_api_token()  # Creates one if missing
    try:
        return render_template('token.html', token=token)
    except:
        return f"<h3>Your API Token</h3><p>{token}</p><p>Keep it secret.</p>"

@app.route("/mfa")
@login_required
def mfa_options():
    return render_template("mfa_options.html", user=current_user)

@app.route("/mfa/recovery_codes")
@login_required
def setup_recovery_codes():
    codes = generate_recovery_codes()

    # Store hashed codes
    current_user.recovery_codes = json.dumps(
        [ph.hash(code) for code in codes]
    )
    current_user.mfa_enabled = True
    db.session.commit()

    log_activity(current_user.id, "recovery_codes_generated")

    return render_template("recovery_codes.html", codes=codes)

@app.route("/mfa/webauthn/auth/start")
def webauthn_auth_start():
    user_id = session.get("pending_mfa_user")
    if not user_id:
        return jsonify({"error": "No pending login"}), 400

    user = User.query.get(user_id)

    credentials = [
        PublicKeyCredentialDescriptor(
            id=cred.credential_id,   # MUST be raw bytes
            type=PublicKeyCredentialType.PUBLIC_KEY
        )
        for cred in user.webauthn_credentials
    ]



    options = generate_authentication_options(
        rp_id=WEBAUTHN_RP_ID,
        allow_credentials=credentials,
        user_verification=UserVerificationRequirement.PREFERRED
    )

    session["webauthn_auth_challenge"] = options.challenge

    return jsonify(json.loads(options_to_json(options)))

@app.route("/mfa/webauthn/auth/finish", methods=["POST"])
def webauthn_auth_finish():
    user_id = session.get("pending_mfa_user")
    if not user_id:
        return jsonify({"error": "No pending login"}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 400

    data = request.json
    challenge = session.get("webauthn_auth_challenge")

    if not challenge:
        return jsonify({"error": "Missing challenge"}), 400

    # 🔐 Decode credential ID safely (base64url → bytes)
    credential_id = base64.urlsafe_b64decode(
        data["id"] + "=" * (-len(data["id"]) % 4)
    )

    cred = WebAuthnCredential.query.filter_by(
        user_id=user.id,
        credential_id=credential_id
    ).first()

    if not cred:
        return jsonify({"error": "Unknown credential"}), 400

    verification = verify_authentication_response(
        credential=data,
        expected_challenge=challenge,
        expected_rp_id=WEBAUTHN_RP_ID,
        expected_origin=WEBAUTHN_ORIGIN,  # ✅ DO NOT hardcode
        credential_public_key=cred.public_key,
        credential_current_sign_count=cred.sign_count,
        require_user_verification=True,
    )

    # 🔄 Update sign counter
    cred.sign_count = verification.new_sign_count
    db.session.commit()

    login_user(user)
    session.pop("pending_mfa_user", None)
    session.pop("webauthn_auth_challenge", None)

    log_activity(user.id, "login_success", meta={"method": "webauthn"})

    return jsonify({"success": True, "redirect": "/dashboard"})


@app.route("/mfa/webauthn/register/start")
@login_required
def webauthn_register_start():
    options = generate_registration_options(
        rp_id=WEBAUTHN_RP_ID,
        rp_name=WEBAUTHN_RP_NAME,
        user_id=str(current_user.id).encode(),
        user_name=current_user.email,
        user_display_name=current_user.email,
        attestation=AttestationConveyancePreference.NONE,
    )

    session["webauthn_register_challenge"] = options.challenge

    return jsonify(json.loads(options_to_json(options)))




@app.route("/mfa/webauthn/register/finish", methods=["POST"])
@login_required
def webauthn_register_finish():
    data = request.json

    challenge = session.get("webauthn_register_challenge")
    if not challenge:
        return jsonify({"success": False, "error": "Missing challenge"}), 400

    verification = verify_registration_response(
        credential=data,
        expected_challenge=challenge,
        expected_rp_id=WEBAUTHN_RP_ID,
        expected_origin=WEBAUTHN_ORIGIN,
        require_user_verification=True,
    )

    # ✅ STORE INTO WebAuthnCredential TABLE (NOT User)
    cred = WebAuthnCredential(
        user_id=current_user.id,
        credential_id=verification.credential_id,
        public_key=verification.credential_public_key,
        sign_count=verification.sign_count,
        transports=",".join(data.get("transports", []))
    )

    db.session.add(cred)

    current_user.webauthn_enabled = True
    current_user.mfa_enabled = True   # ✅ ADD THIS
    db.session.commit()

    session.pop("webauthn_register_challenge", None)

    return jsonify({"success": True})




# ===========================
# Run the App
# ===========================
if __name__ == "__main__":
    app.run(debug=True)
