import smtplib
import random
import time
from email.message import EmailMessage
from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, EmailStr
from typing import Dict
import uvicorn

app = FastAPI()

# --- CONFIGURATION ---
SENDER_EMAIL = "ariyanxd02@gmail.com"
SENDER_PASSWORD = "xvcbgglrppbnwhlt" # App Password (spaces removed)
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
        return "<h2 style='text-align:center;margin-top:50px;'>Server is Live! But index.html not found.</h2>"

# --- Request OTP ---
@app.post("/request-otp")
async def request_otp(data: OTPRequest, key: str = Depends(verify_api_key)):
    email = data.email
    current_time = time.time()

    # Initialize spam monitor
    if email not in spam_monitor:
        spam_monitor[email] = {"attempts": 0, "block_until": 0}

    user_data = spam_monitor[email]

    # Block check
    if current_time < user_data["block_until"]:
        remaining = int(user_data["block_until"] - current_time)
        raise HTTPException(status_code=429, detail=f"Spam protection! Try after {remaining} seconds.")

    # Reset attempts after block period or 10 mins of inactivity
    if current_time > user_data["block_until"] and user_data["block_until"] != 0:
        user_data["attempts"] = 0
        user_data["block_until"] = 0

    user_data["attempts"] += 1

    # Block after 10 attempts
    if user_data["attempts"] > 10:
        user_data["block_until"] = current_time + 300 # 5 min block
        raise HTTPException(status_code=429, detail="Too many attempts. Blocked for 5 mins.")

    otp = str(random.randint(100000, 999999))

    try:
        # Email Setup
        msg = EmailMessage()
        msg["Subject"] = f"Your OTP: {otp}"
        msg["From"] = SENDER_EMAIL
        msg["To"] = email
        msg.set_content(f"Hello,\n\nYour verification code is: {otp}\n\nThis code will expire in 5 minutes.\nDo not share this code with anyone.")

        # SMTP Connection using TLS (Port 587 is more stable on Render)
        with smtplib.SMTP("smtp.gmail.com", 587, timeout=15) as server:
            server.starttls() # Secure the connection
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.send_message(msg)

        # Store OTP with 5 min expiry
        otp_storage[email] = {
            "otp": otp,
            "expires_at": current_time + 300
        }

        return {"status": "success", "message": "OTP Sent Successfully"}

    except smtplib.SMTPAuthenticationError:
        raise HTTPException(status_code=500, detail="Gmail Authentication Failed. Check App Password.")
    except Exception as e:
        # detailed error for debugging
        raise HTTPException(status_code=500, detail=f"Network Error: {str(e)}")

# --- Verify OTP ---
@app.post("/verify-otp")
async def verify_otp(data: OTPVerify, key: str = Depends(verify_api_key)):
    email = data.email
    otp_code = data.otp_code

    stored = otp_storage.get(email)

    if not stored:
        raise HTTPException(status_code=400, detail="No OTP record found. Please request a new one.")

    # Expiry Check
    if time.time() > stored["expires_at"]:
        del otp_storage[email]
        raise HTTPException(status_code=400, detail="OTP Expired. Please request a new one.")

    # Match Check
    if stored["otp"] == otp_code:
        del otp_storage[email] # Clear after success
        if email in spam_monitor:
            spam_monitor[email]["attempts"] = 0 # Reset spam count
        return {"status": "verified", "message": "Verification Successful"}

    raise HTTPException(status_code=400, detail="Incorrect OTP. Please check and try again.")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
