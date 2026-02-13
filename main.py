import smtplib
import random
import time
import os
from email.message import EmailMessage
from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, EmailStr
from typing import Dict
import uvicorn

app = FastAPI()

# --- CONFIGURATION (Directly Added Your Info) ---
SENDER_EMAIL = "ariyanxd02@gmail.com"
SENDER_PASSWORD = "xvcb gglr ppbn whlt"  # আপনার নতুন অ্যাপ পাসওয়ার্ড
ACCESS_KEY = "ariyan-secret-key-2026"

otp_storage: Dict[str, dict] = {}
spam_monitor: Dict[str, dict] = {}

# --- Request Models ---
class OTPRequest(BaseModel):
    email: EmailStr

class OTPVerify(BaseModel):
    email: EmailStr
    otp_code: str

# --- API Key Verify ---
def verify_api_key(access_key: str = Header(None)):
    if access_key != ACCESS_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized Access")
    return access_key

# --- Home Route ---
@app.get("/", response_class=HTMLResponse)
async def read_index():
    try:
        with open("index.html", "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return "<h2>Server Running - index.html not found</h2>"

# --- Request OTP ---
@app.post("/request-otp")
async def request_otp(data: OTPRequest, key: str = Depends(verify_api_key)):
    email = data.email
    current_time = time.time()

    if email not in spam_monitor:
        spam_monitor[email] = {"attempts": 0, "block_until": 0}

    user_data = spam_monitor[email]

    # Block check
    if current_time < user_data["block_until"]:
        remaining = int(user_data["block_until"] - current_time)
        raise HTTPException(status_code=429, detail=f"Blocked for spamming. Try after {remaining} seconds.")

    # Reset attempts after block time is over
    if current_time > user_data["block_until"] and user_data["block_until"] != 0:
        user_data["attempts"] = 0
        user_data["block_until"] = 0

    user_data["attempts"] += 1

    # Blocking after 10 attempts (As you requested earlier)
    if user_data["attempts"] > 10:
        user_data["block_until"] = current_time + 300 # 5 mins block
        raise HTTPException(status_code=429, detail="Spam detected. Blocked for 5 mins.")

    otp = str(random.randint(100000, 999999))

    try:
        msg = EmailMessage()
        msg["Subject"] = f"OTP Code: {otp}"
        msg["From"] = SENDER_EMAIL
        msg["To"] = email
        msg.set_content(f"Your verification code is: {otp}\nExpires in 5 minutes.")

        # Using SMTP_SSL for fast delivery
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.send_message(msg)

        otp_storage[email] = {
            "otp": otp,
            "expires_at": current_time + 300
        }

        return {"status": "success", "message": "OTP Sent Successfully", "attempts": user_data["attempts"]}

    except smtplib.SMTPAuthenticationError:
        raise HTTPException(status_code=500, detail="Email Auth Failed. Check App Password.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# --- Verify OTP ---
@app.post("/verify-otp")
async def verify_otp(data: OTPVerify, key: str = Depends(verify_api_key)):
    email = data.email
    otp_code = data.otp_code

    stored = otp_storage.get(email)

    if not stored:
        raise HTTPException(status_code=400, detail="No OTP Requested for this email")

    if time.time() > stored["expires_at"]:
        del otp_storage[email]
        raise HTTPException(status_code=400, detail="OTP Expired")

    if stored["otp"] == otp_code:
        del otp_storage[email]
        # Reset spam on success
        if email in spam_monitor:
            spam_monitor[email]["attempts"] = 0
        return {"status": "verified", "message": "Verification Complete"}

    raise HTTPException(status_code=400, detail="Wrong OTP")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
