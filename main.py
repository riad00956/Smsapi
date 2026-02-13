import smtplib
import random
import time
import os
from flask import Flask, request, jsonify, render_template_string
from email.message import EmailMessage

app = Flask(__name__)

# --- CONFIGURATION ---
SENDER_EMAIL = "ariyanxd02@gmail.com"
SENDER_PASSWORD = "xvcbgglrppbnwhlt"
ACCESS_KEY = "ariyan-secret-key-2026"

otp_storage = {}
spam_monitor = {}

# --- HELPER: Verify API Key ---
def check_key():
    key = request.headers.get("access-key")
    if key != ACCESS_KEY:
        return False
    return True

# --- HOME ROUTE (Using index.html) ---
@app.route('/')
def index():
    try:
        with open("index.html", "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return "<h2>Flask Server Live. index.html missing!</h2>"

# --- REQUEST OTP API ---
@app.route('/request-otp', methods=['POST'])
def request_otp():
    if not check_key():
        return jsonify({"detail": "Unauthorized Access"}), 401

    data = request.json
    email = data.get("email")
    current_time = time.time()

    if not email:
        return jsonify({"detail": "Email is required"}), 400

    # Spam Protection
    if email not in spam_monitor:
        spam_monitor[email] = {"attempts": 0, "block_until": 0}
    
    user_data = spam_monitor[email]
    if current_time < user_data["block_until"]:
        rem = int(user_data["block_until"] - current_time)
        return jsonify({"detail": f"Blocked! Try after {rem}s"}), 429

    otp = str(random.randint(100000, 999999))

    try:
        msg = EmailMessage()
        msg["Subject"] = f"Your OTP: {otp}"
        msg["From"] = SENDER_EMAIL
        msg["To"] = email
        msg.set_content(f"Verification Code: {otp}")

        # Port 587 is more reliable on Flask/Render
        with smtplib.SMTP("smtp.gmail.com", 587, timeout=10) as server:
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.send_message(msg)

        otp_storage[email] = {"otp": otp, "expires_at": current_time + 300}
        user_data["attempts"] += 1
        
        if user_data["attempts"] > 10:
            user_data["block_until"] = current_time + 300
            user_data["attempts"] = 0

        return jsonify({"status": "success", "message": "OTP Sent Successfully"})

    except Exception as e:
        return jsonify({"detail": f"Network Error: {str(e)}"}), 500

# --- VERIFY OTP API ---
@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    if not check_key():
        return jsonify({"detail": "Unauthorized"}), 401

    data = request.json
    email = data.get("email")
    otp_code = data.get("otp_code")

    stored = otp_storage.get(email)
    if not stored or time.time() > stored["expires_at"]:
        return jsonify({"detail": "OTP Expired or Not Found"}), 400
    
    if stored["otp"] == otp_code:
        del otp_storage[email]
        return jsonify({"status": "verified"})
    
    return jsonify({"detail": "Invalid OTP"}), 400

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
