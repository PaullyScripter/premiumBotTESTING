import os
import secrets
from urllib.parse import urlencode

from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi import APIRouter
from fastapi import Body
from fastapi import Header
import httpx
import os
from pathlib import Path
from dotenv import load_dotenv
import hashlib
import json
import httpx
from typing import Literal
import hashlib
import base64
from subscriptions import add_subscription, user_is_active


# Always load the .env that lives in the same folder as main.py
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID")
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET")
DISCORD_REDIRECT_URI = os.getenv("DISCORD_REDIRECT_URI")
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:8888")

CRYPTOMUS_MERCHANT_ID = os.getenv("CRYPTOMUS_MERCHANT_ID")
CRYPTOMUS_API_KEY = os.getenv("CRYPTOMUS_API_KEY")


print("DEBUG DISCORD_CLIENT_ID:", repr(DISCORD_CLIENT_ID))
print("DEBUG DISCORD_REDIRECT_URI:", repr(DISCORD_REDIRECT_URI))

if not DISCORD_CLIENT_ID or not DISCORD_CLIENT_SECRET or not DISCORD_REDIRECT_URI:
    print("⚠️ Set DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, DISCORD_REDIRECT_URI in .env")


app = FastAPI()

FRONTEND_ORIGINS = [
    "http://localhost:5500",                 # local dev
    "https://equinoxbot.netlify.app",        # your real Netlify site
]


# allow your Netlify site to talk to this backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=FRONTEND_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

sessions: dict[str, dict] = {}


def make_avatar_url(user: dict) -> str:
    avatar_hash = user.get("avatar")
    user_id = user["id"]
    if avatar_hash:
        ext = "gif" if avatar_hash.startswith("a_") else "png"
        return f"https://cdn.discordapp.com/avatars/{user_id}/{avatar_hash}.{ext}?size=128"
    # default avatar
    discrim = int(user.get("discriminator", "0")) % 5
    return f"https://cdn.discordapp.com/embed/avatars/{discrim}.png"


def get_user_from_session(request: Request) -> dict | None:
    session_id = request.cookies.get("session_id")
    if not session_id:
        return None
    return sessions.get(session_id)

def cryptomus_sign(payload: dict) -> str:
    """
    Build Cryptomus signature based on docs:
    signature = md5(json_string + api_key)
    """
    if not CRYPTOMUS_API_KEY:
        raise RuntimeError("CRYPTOMUS_API_KEY not set")

    # JSON with sorted keys, no spaces
    json_str = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    raw = json_str + CRYPTOMUS_API_KEY
    return hashlib.md5(raw.encode("utf-8")).hexdigest()

def _cryptomus_build_sign_body(data: dict) -> str:
    """
    Build JSON exactly how Cryptomus expects:
    - ensure_ascii=False
    - separators=(',', ':')
    - slashes escaped as \/
    """
    json_str = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    json_str = json_str.replace("/", r"\/")  # match PHP behavior Cryptomus expects
    return json_str

def cryptomus_sign_request_body(body_str: str) -> str:
    """
    Sign for /v1/payment:
    MD5( base64( body_str ) + API_KEY )
    """
    if not CRYPTOMUS_API_KEY:
        raise RuntimeError("CRYPTOMUS_API_KEY not set")

    b64 = base64.b64encode(body_str.encode("utf-8")).decode("utf-8")
    return hashlib.md5((b64 + CRYPTOMUS_API_KEY).encode("utf-8")).hexdigest()

def cryptomus_sign(data: dict) -> str:
    """
    Signature for verifying incoming webhook:
    MD5(base64(JSON-without-sign) + API_KEY)
    """
    tmp = dict(data)
    if "sign" in tmp:
        tmp.pop("sign")

    json_str = _cryptomus_build_sign_body(tmp)
    b64 = base64.b64encode(json_str.encode("utf-8")).decode("utf-8")
    return hashlib.md5((b64 + CRYPTOMUS_API_KEY).encode("utf-8")).hexdigest()

@app.get("/api/premium/{discord_id}")
def api_premium(discord_id: int):
    """
    Bot and frontend can call this to see if a user is premium.
    """
    active, tier, expires = user_is_active(discord_id)
    return {
        "premium": active,
        "tier": tier,
        "expires_at": expires,
    }

@app.get("/auth/discord/login")
async def discord_login():
    """
    Redirects the user to Discord's OAuth2 page.
    """
    params = {
        "client_id": DISCORD_CLIENT_ID,
        "redirect_uri": DISCORD_REDIRECT_URI,
        "response_type": "code",
        "scope": "identify",
    }
    url = "https://discord.com/api/oauth2/authorize?" + urlencode(params)
    return RedirectResponse(url)


@app.get("/auth/discord/callback")
async def discord_callback(code: str | None = None, error: str | None = None):
    """
    Discord redirects here with ?code=...
    We exchange it for a token, get the user, and create a simple session.
    This version prints useful debug info instead of a generic 500 error.
    """
    if error:
        # Discord sent an error like access_denied
        raise HTTPException(status_code=400, detail=f"Discord OAuth error: {error}")

    if not code:
        raise HTTPException(status_code=400, detail="Missing 'code' parameter")

    token_url = "https://discord.com/api/oauth2/token"
    data = {
        "client_id": DISCORD_CLIENT_ID,
        "client_secret": DISCORD_CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": DISCORD_REDIRECT_URI,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    try:
        async with httpx.AsyncClient() as client:
            token_res = await client.post(token_url, data=data, headers=headers, timeout=10)
            print("TOKEN RESPONSE STATUS:", token_res.status_code)
            print("TOKEN RESPONSE BODY:", token_res.text)
            token_res.raise_for_status()
            token_data = token_res.json()
            access_token = token_data["access_token"]

            user_res = await client.get(
                "https://discord.com/api/users/@me",
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=10,
            )
            print("USER RESPONSE STATUS:", user_res.status_code)
            print("USER RESPONSE BODY:", user_res.text)
            user_res.raise_for_status()
            user = user_res.json()
    except httpx.HTTPError as e:
        # show error clearly instead of generic 500
        raise HTTPException(status_code=500, detail=f"HTTP error talking to Discord: {e}")

    session_id = secrets.token_urlsafe(32)
    sessions[session_id] = user

    response = RedirectResponse(FRONTEND_URL)
    IS_PROD = os.getenv("ENV", "dev") == "prod"

    response.set_cookie(
        "session_id",
        session_id,
        httponly=True,
        secure=IS_PROD,  # True on Render, False locally if you like
        samesite="none" if IS_PROD else "lax",
        max_age=60 * 60 * 24 * 7,
    )
    return response



@app.post("/auth/logout")
async def logout(request: Request):
    user = get_user_from_session(request)
    response = JSONResponse({"ok": True})
    if user:
        session_id = request.cookies.get("session_id")
        sessions.pop(session_id, None)
        response.delete_cookie("session_id")
    return response


@app.get("/api/me")
def me(request: Request):
    user = get_user_from_session(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not logged in")

    # Discord user data from OAuth
    discord_id = int(user["id"])
    active, tier, expires = user_is_active(discord_id)

    return {
        "id": discord_id,
        "username": user["username"],
        "discriminator": user["discriminator"],
        "avatar": user["avatar"],
        "avatar_url": make_avatar_url(user),  # your existing helper
        "premium": active,
        "tier": tier,
        "expires_at": expires,
    }


@app.post("/api/create-invoice")
async def create_invoice(request: Request, body: dict = Body(...)):
    """
    Create a Cryptomus payment invoice for the logged-in user.
    Expects JSON body: { "plan": "monthly" | "yearly" | "lifetime" }
    """
    user = get_user_from_session(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not logged in")

    if not CRYPTOMUS_MERCHANT_ID or not CRYPTOMUS_API_KEY:
        raise HTTPException(status_code=500, detail="Cryptomus not configured")

    plan = (body.get("plan") or "monthly").lower()

    if plan == "monthly":
        amount = "5.00"
    elif plan == "yearly":
        amount = "40.00"
    elif plan == "lifetime":
        amount = "80.00"
    else:
        raise HTTPException(status_code=400, detail="Invalid plan")

    discord_id = str(user["id"])

    custom_data = {
        "discord_id": discord_id,
        "plan": plan,
    }

    # where to send the user back if they click "Back to site" on the payment page
    url_return = FRONTEND_URL or "https://equinoxbot.netlify.app/premium.html"
    url_success = "https://equinoxbot.netlify.app/thankyou.html"

    # our webhook endpoint (this is the important part!)
    base_url = f"{request.url.scheme}://{request.url.netloc}"
    url_callback = f"{base_url}/api/cryptomus/webhook"

    order_id = f"{discord_id}-{plan}-{secrets.token_hex(4)}"

    invoice_payload = {
        "amount": amount,
        "currency": "USD",
        "order_id": order_id,
        "url_return": url_return,
        "url_success": url_success,   
        "url_callback": url_callback,
        "is_payment_multiple": False,
        "lifetime": 3600,
        "additional_data": json.dumps(custom_data, ensure_ascii=False),
    }

    # 1) build the exact JSON string Cryptomus will receive
    body_str = json.dumps(invoice_payload, ensure_ascii=False, separators=(",", ":"))

    # 2) compute sign from that string
    sign = cryptomus_sign_request_body(body_str)

    headers = {
        "merchant": CRYPTOMUS_MERCHANT_ID,
        "sign": sign,
        "Content-Type": "application/json",
    }

    # 3) send that same string as the body
    async with httpx.AsyncClient() as client_http:
        res = await client_http.post(
            "https://api.cryptomus.com/v1/payment",
            headers=headers,
            content=body_str.encode("utf-8"),
            timeout=20,
        )

    print("CRYPTOMUS INVOICE STATUS:", res.status_code)
    print("CRYPTOMUS INVOICE BODY:", res.text)

    if res.status_code != 200:
        raise HTTPException(status_code=502, detail="Failed to create invoice")

    data = res.json()

    # According to the docs you pasted, response is:
    # { "state": 0, "result": { ... "url": "https://pay.cryptomus.com/pay/..." } }
    result = data.get("result") or {}
    invoice_url = result.get("url")
    if not invoice_url:
        raise HTTPException(status_code=502, detail="Invoice URL missing in response")

    return {
        "invoice_url": invoice_url,
        "order_id": result.get("order_id") or order_id,
        "uuid": result.get("uuid"),
    }


@app.post("/api/cryptomus/webhook")
async def cryptomus_webhook(
    payload: dict = Body(...),
    sign: str | None = Header(default=None),
):
    """
    Secure Cryptomus webhook:

    - Verifies signature using payment API key
    - Only acts on 'paid' / 'paid_over'
    - Requires valid discord_id + plan in additional_data/custom
    - Writes subscription via add_subscription()
    """
    if not CRYPTOMUS_MERCHANT_ID or not CRYPTOMUS_API_KEY:
        raise HTTPException(status_code=500, detail="Cryptomus not configured")

    if not sign:
        raise HTTPException(status_code=400, detail="Missing signature header")

    # Some webhooks wrap data in "result"
    data = payload.get("result") if isinstance(payload.get("result"), dict) else payload

    # Verify signature
    expected_sign = cryptomus_sign(data)  # make sure this matches your helper
    if sign != expected_sign:
        print("❌ Invalid Cryptomus signature")
        raise HTTPException(status_code=401, detail="Invalid signature")

    print("=== CRYPTOMUS WEBHOOK (verified) ===")
    print(json.dumps(data, indent=2, ensure_ascii=False))

    status = data.get("status") or data.get("payment_status")
    if status not in ("paid", "paid_over"):
        print("Non-paid status, ignoring:", status)
        return {"ok": True, "message": f"Ignored status {status}"}

    # Read custom data (what you passed as additional_data/custom in /v1/payment)
    custom_raw = (
        data.get("additional_data")
        or data.get("custom")
        or "{}"
    )

    try:
        custom = json.loads(custom_raw)
    except Exception as e:
        print("Failed to parse additional_data/custom:", e, custom_raw)
        custom = {}

    discord_id = custom.get("discord_id")
    plan = custom.get("plan")

    if not discord_id or not plan:
        # For security, do NOT auto grant anything if these are missing
        print("Missing discord_id/plan in webhook custom data; ignoring.")
        return {"ok": True, "message": "Missing discord_id/plan; no subscription granted"}

    invoice_id = (
        data.get("uuid")
        or data.get("transaction_id")
        or data.get("order_id")
        or "cryptomus"
    )

    try:
        add_subscription(int(discord_id), plan, invoice_id)
        print(f"✅ Granted {plan} subscription to {discord_id} with code={invoice_id}")
    except Exception as e:
        print("❌ ERROR writing subscription:", e)
        raise HTTPException(status_code=500, detail="Failed to write subscription")

    return {"ok": True, "message": f"Subscription granted for {discord_id} ({plan})"}








@app.get("/")
async def root():
    return {"ok": True}
