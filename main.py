import smtplib
import random
import time
from email.message import EmailMessage
from fastapi import FastAPI, HTTPException, Header, Depends, Query
from fastapi.responses import HTMLResponse
from typing import Dict
import uvicorn

app = FastAPI()

# --- CONFIGURATION ---
SENDER_EMAIL = "ariyanxd02@gmail.com"
SENDER_PASSWORD = "xvcb gglr ppbn whlt"
ACCESS_KEY = "ariyan-secret-key-2026"

otp_storage: Dict[str, dict] = {}
spam_monitor: Dict[str, dict] = {}

def verify_api_key(access_key: str = Header(None)):
    if access_key != ACCESS_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized Access")
    return access_key

# Home route to show index.html
@app.get("/", response_class=HTMLResponse)
async def read_index():
    with open("index.html", "r", encoding="utf-8") as f:
        return f.read()

@app.post("/request-otp")
async def request_otp(email: str, key: str = Depends(verify_api_key)):
    current_time = time.time()
    if email not in spam_monitor:
        spam_monitor[email] = {"attempts": 0, "block_until": 0}

    user_data = spam_monitor[email]
    if current_time < user_data["block_until"]:
        raise HTTPException(status_code=429, detail="Blocked for spamming. Try later.")

    user_data["attempts"] += 1
    if user_data["attempts"] > 10:
        user_data["block_until"] = current_time + 300
        user_data["attempts"] = 0
        raise HTTPException(status_code=429, detail="Spam detected. Blocked for 5 mins.")

    otp = str(random.randint(100000, 999999))
    try:
        msg = EmailMessage()
        msg['Subject'] = f"OTP: {otp}"
        msg['From'] = SENDER_EMAIL
        msg['To'] = email
        msg.set_content(f"Your verification code is: {otp}\nExpires in 5 mins.")
        
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.send_message(msg)
        
        otp_storage[email] = {"otp": otp, "expires_at": current_time + 300}
        return {"status": "success", "message": "OTP Sent"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/verify-otp")
async def verify_otp(email: str, otp_code: str, key: str = Depends(verify_api_key)):
    data = otp_storage.get(email)
    if not data or time.time() > data["expires_at"]:
        raise HTTPException(status_code=400, detail="OTP Expired or Invalid")
    
    if data["otp"] == otp_code:
        del otp_storage[email]
        return {"status": "verified"}
    raise HTTPException(status_code=400, detail="Wrong OTP")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
      
