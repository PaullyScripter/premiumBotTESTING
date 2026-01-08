import os
import secrets
from urllib.parse import urlencode
import psycopg
from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse
from pydantic import BaseModel
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
from fastapi import Query
from subscriptions import (
    add_subscription,
    user_is_active,
    grant_subscription_from_webhook,
    grant_subscription_from_sellauth_webhook
)
from urllib.parse import urlencode, urlparse
from datetime import datetime, timedelta, timezone
import re 

DATABASE_URL = os.getenv("DATABASE_URL")
REDEEM_CODE_PEPPER = os.getenv("REDEEM_CODE_PEPPER")


def get_db():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL not set")
    return psycopg.connect(DATABASE_URL, sslmode="require")



def hash_redeem_code(raw: str) -> str:
    return hashlib.sha256((PEPPER + raw).encode("utf-8")).hexdigest()



# Always load the .env that lives in the same folder as main.py
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID")
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET")
DISCORD_REDIRECT_URI = os.getenv("DISCORD_REDIRECT_URI")
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:8888")

CRYPTOMUS_MERCHANT_ID = os.getenv("CRYPTOMUS_MERCHANT_ID")
CRYPTOMUS_API_KEY = os.getenv("CRYPTOMUS_API_KEY")
SELLAUTH_WEBHOOK_SECRET = os.getenv("SELLAUTH_WEBHOOK_SECRET", "change-me")

SELLAUTH_API_KEY = os.getenv("SELLAUTH_API_KEY", "")
SELLAUTH_SHOP_ID = os.getenv("SELLAUTH_SHOP_ID", "")

if not SELLAUTH_API_KEY:
    print("WARNING: SELLAUTH_API_KEY is not set")
if not SELLAUTH_SHOP_ID:
    print("WARNING: SELLAUTH_SHOP_ID is not set")


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


def safe_next(next_url: str | None) -> str:
    if not next_url:
        return FRONTEND_URL

    next_url = next_url.strip()

    # allow relative
    if next_url.startswith("/"):
        return next_url

    # allow absolute ONLY to your own frontend
    try:
        u = urlparse(next_url)
        if u.scheme in ("http", "https") and u.netloc in ALLOWED_FRONTEND_HOSTS:
            return next_url
    except Exception:
        pass

    return FRONTEND_URL

@app.get("/auth/discord/login")
async def discord_login(next: str | None = Query(default=None)):
    # make a random state token
    state = secrets.token_urlsafe(16)

    # store where to go after login
    sessions[f"oauth_state:{state}"] = safe_next(next)

    params = {
        "client_id": DISCORD_CLIENT_ID,
        "redirect_uri": DISCORD_REDIRECT_URI,
        "response_type": "code",
        "scope": "identify",
        "state": state,  # ✅ MUST be the token
    }

    url = "https://discord.com/api/oauth2/authorize?" + urlencode(params)
    return RedirectResponse(url)

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

def cryptomus_sign_string(json_str: str) -> str:
    """
    Signature as Cryptomus expects for webhook:
    md5( raw_json_string + PAYMENT_API_KEY )
    """
    if not CRYPTOMUS_API_KEY:
        raise RuntimeError("CRYPTOMUS_API_KEY not set")
    return hashlib.md5((json_str + CRYPTOMUS_API_KEY).encode("utf-8")).hexdigest()


def _cryptomus_build_sign_body(data: dict) -> str:
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

def cryptomus_verify_webhook_signature(raw_body: bytes, header_sign: str | None) -> dict:
    """
    Verify Cryptomus webhook signature using the Payment API key.

    According to their webhook docs:
      sign = md5(json_string + PAYMENT_API_KEY)
    """
    if not CRYPTOMUS_API_KEY:
        raise HTTPException(status_code=500, detail="Cryptomus API key not configured")

    if not header_sign:
        raise HTTPException(status_code=400, detail="Missing signature")

    # Use the RAW JSON string as sent in HTTP body
    json_str = raw_body.decode("utf-8")

    # Build expected sign
    expected = hashlib.md5((json_str + CRYPTOMUS_API_KEY).encode("utf-8")).hexdigest()

    # Debug log (safe – does not print the API key)
    print("WEBHOOK HEADER SIGN:", header_sign)
    print("WEBHOOK EXPECTED SIGN:", expected)
    print("WEBHOOK RAW BODY:", json_str)

    if header_sign != expected:
        # Signature wrong → don't grant premium
        raise HTTPException(status_code=401, detail="Invalid signature")

    # Parse JSON payload after signature check
    try:
        payload = json.loads(json_str)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    return payload
    
ALLOWED_FRONTEND_HOSTS = {"equinoxbot.netlify.app"}  # change if needed

def safe_next_url(next_url: str | None) -> str:
    if not next_url:
        return FRONTEND_URL
    try:
        u = urlparse(next_url)
        if u.scheme in ("http", "https") and u.netloc in ALLOWED_FRONTEND_HOSTS:
            return next_url
    except Exception:
        pass
    return FRONTEND_URL


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



@app.get("/auth/discord/callback")
async def discord_callback(
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
):
    """
    Discord redirects here with ?code=...&state=...
    We exchange it for a token, get the user, create a session,
    then redirect back to the page user started login from.
    """
    if error:
        raise HTTPException(status_code=400, detail=f"Discord OAuth error: {error}")

    if not code:
        raise HTTPException(status_code=400, detail="Missing 'code' parameter")

    if not state:
        raise HTTPException(status_code=400, detail="Missing 'state' parameter")

    # ✅ retrieve where the user wanted to go back to
    next_url = sessions.pop(f"oauth_state:{state}", FRONTEND_URL)
    next_url = safe_next(next_url)

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
        raise HTTPException(status_code=500, detail=f"HTTP error talking to Discord: {e}")

    session_id = secrets.token_urlsafe(32)
    sessions[session_id] = user

    # ✅ redirect back to where they started
    response = RedirectResponse(next_url)

    response.set_cookie(
        "session_id",
        session_id,
        httponly=True,
        secure=True,
        # If you're using Netlify proxy (same-origin), Lax is best:
        samesite="lax",
        max_age=60 * 60 * 24 * 7,
    )
    return response


@app.get("/api/subscription")
def api_subscription(request: Request):
    user = get_user_from_session(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not logged in")

    discord_id = int(user["id"])

    active, tier, expires = user_is_active(discord_id)

    started_at = None
    code_used = None

    try:
        import psycopg
        db_url = os.getenv("DATABASE_URL")
        if db_url:
            with psycopg.connect(db_url, sslmode="require") as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        select tier, redeemed_at, expires_at, last_code_hash
                        from user_subscriptions
                        where discord_id = %s
                        order by redeemed_at desc
                        limit 1
                        """,
                        (discord_id,),
                    )
                    row = cur.fetchone()
                    if row:
                        tier, started_at, expires, last_hash = row
                        code_used = f"...{str(last_hash)[-8:]}" if last_hash else None

                        now = datetime.now(timezone.utc)
                        if tier == "lifetime" or expires is None:
                            active = True
                        else:
                            # make expires timezone-aware if needed
                            if getattr(expires, "tzinfo", None) is None:
                                expires = expires.replace(tzinfo=timezone.utc)
                            active = expires > now
    except Exception as e:
        print("api_subscription db lookup failed:", e)

    return {
        "premium": active,
        "tier": tier,
        "started_at": started_at,
        "expires_at": expires,
        "code_used": code_used,
    }



@app.post("/auth/logout")
async def logout(request: Request):
    user = get_user_from_session(request)
    response = JSONResponse({"ok": True})
    if user:
        session_id = request.cookies.get("session_id")
        sessions.pop(session_id, None)
        response.delete_cookie("session_id", secure=True, samesite="lax")
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

@app.get("/api/premium")
def api_premium_me(request: Request):
    """
    Premium status for the currently logged-in user (via Discord session).
    Frontend uses this for premium.html and thankyou.html.
    """
    user = get_user_from_session(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not logged in")

    discord_id = int(user["id"])
    active, tier, expires = user_is_active(discord_id)

    return {
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

    # 💰 real prices here:
    if plan == "monthly":
        amount = "2.99"
    elif plan == "yearly":
        amount = "29.99"
    elif plan == "lifetime":
        amount = "10.10"
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
        "is_payment_multiple": True,
        "lifetime": 7200,
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
    request: Request,
    sign: str | None = Header(default=None),
):
    """
    Real Cryptomus webhook:
    - verify signature using PAYMENT API KEY
    - accept only 'paid' / 'paid_over'
    - read custom / additional_data { discord_id, plan }
    - grant subscription by writing JSON
    """
    if not CRYPTOMUS_MERCHANT_ID or not CRYPTOMUS_API_KEY:
        raise HTTPException(status_code=500, detail="Cryptomus not configured")

    # Read raw body exactly as Cryptomus sent it
    raw_body = await request.body()

    # 1) Verify signature and parse JSON
    payload = cryptomus_verify_webhook_signature(raw_body, sign)

    status = payload.get("status")
    print("WEBHOOK STATUS FIELD:", status)

    # 2) Only handle successful payments
    if status not in ("paid", "paid_over"):
        # Log and ignore everything else (check, process, cancel, etc.)
        print("WEBHOOK IGNORED STATUS:", status)
        return {"ok": True, "message": f"Ignored status {status}"}

    # 3) Extract our custom data
    #    We used "additional_data" when creating invoices.
    #    Some setups use "custom". Support both just in case.
    custom_raw = payload.get("custom") or payload.get("additional_data") or "{}"
    print("WEBHOOK CUSTOM RAW:", custom_raw)

    try:
        custom = json.loads(custom_raw)
    except Exception:
        custom = {}
        print("WEBHOOK CUSTOM PARSE FAILED, GOT EMPTY DICT")

    discord_id = custom.get("discord_id")
    plan = custom.get("plan")

    print("WEBHOOK DISCORD_ID:", discord_id)
    print("WEBHOOK PLAN:", plan)

    if not discord_id or not plan:
        raise HTTPException(
            status_code=400,
            detail="Missing discord_id or plan in webhook data",
        )

    # 4) Grant subscription using your JSON-based logic
    try:
        grant_subscription_from_webhook(int(discord_id), plan, payload)
    except Exception as e:
        print("ERROR in grant_subscription_from_webhook:", e)
        raise HTTPException(status_code=500, detail="Failed to grant subscription")

    print(f"WEBHOOK SUCCESSFULLY GRANTED {plan} TO {discord_id}")
    return {"ok": True, "message": f"Subscription granted for {discord_id} ({plan})"}
# @app.post("/api/cryptomus/webhook")
# async def cryptomus_webhook(
#     payload: dict = Body(...),
#     sign: str | None = Header(default=None),
# ):
#     """
#     Secure Cryptomus webhook:

#     - Verifies signature using payment API key
#     - Only acts on 'paid' / 'paid_over'
#     - Requires valid discord_id + plan in additional_data/custom
#     - Writes subscription via add_subscription()
#     """
#     if not CRYPTOMUS_MERCHANT_ID or not CRYPTOMUS_API_KEY:
#         raise HTTPException(status_code=500, detail="Cryptomus not configured")

#     if not sign:
#         raise HTTPException(status_code=400, detail="Missing signature header")

#     # Some webhooks wrap data in "result"
#     data = payload.get("result") if isinstance(payload.get("result"), dict) else payload

#     # Verify signature
#     expected_sign = cryptomus_sign(data)  # make sure this matches your helper
#     if sign != expected_sign:
#         print("❌ Invalid Cryptomus signature")
#         raise HTTPException(status_code=401, detail="Invalid signature")

#     print("=== CRYPTOMUS WEBHOOK (verified) ===")
#     print(json.dumps(data, indent=2, ensure_ascii=False))

#     status = data.get("status") or data.get("payment_status")
#     if status not in ("paid", "paid_over"):
#         print("Non-paid status, ignoring:", status)
#         return {"ok": True, "message": f"Ignored status {status}"}

#     # Read custom data (what you passed as additional_data/custom in /v1/payment)
#     custom_raw = (
#         data.get("additional_data")
#         or data.get("custom")
#         or "{}"
#     )

#     try:
#         custom = json.loads(custom_raw)
#     except Exception as e:
#         print("Failed to parse additional_data/custom:", e, custom_raw)
#         custom = {}

#     discord_id = custom.get("discord_id")
#     plan = custom.get("plan")

#     if not discord_id or not plan:
#         # For security, do NOT auto grant anything if these are missing
#         print("Missing discord_id/plan in webhook custom data; ignoring.")
#         return {"ok": True, "message": "Missing discord_id/plan; no subscription granted"}

#     invoice_id = (
#         data.get("uuid")
#         or data.get("transaction_id")
#         or data.get("order_id")
#         or "cryptomus"
#     )

#     try:
#         add_subscription(int(discord_id), plan, invoice_id)
#         print(f"✅ Granted {plan} subscription to {discord_id} with code={invoice_id}")
#     except Exception as e:
#         print("❌ ERROR writing subscription:", e)
#         raise HTTPException(status_code=500, detail="Failed to write subscription")

#     return {"ok": True, "message": f"Subscription granted for {discord_id} ({plan})"}

CODE_PATTERN = re.compile(r"^[A-Za-z0-9]{4}(-[A-Za-z0-9]{4}){3}$")
@app.post("/api/redeem")
def redeem_code(request: Request, body: dict = Body(...)):
    user = get_user_from_session(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not logged in")

    code = (body.get("code") or "").strip()
    if not code:
        raise HTTPException(status_code=400, detail="Redeem failed. Please try another code.")

    # ✅ STRICT format check (with dashes, case-sensitive)
    if not CODE_PATTERN.fullmatch(code):
        raise HTTPException(status_code=400, detail="Redeem failed. Please try another code.")

    pepper = os.getenv("REDEEM_CODE_PEPPER")
    if not pepper:
        raise HTTPException(status_code=500, detail="Server misconfigured")

    code_hash = hashlib.sha256((pepper + code).encode("utf-8")).hexdigest()
    discord_id = int(user["id"])
    now = datetime.now(timezone.utc)

    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT id, tier, used_at
                    FROM redeem_codes
                    WHERE code_hash = %s
                    FOR UPDATE
                    """,
                    (code_hash,),
                )
                row = cur.fetchone()

                # ❌ invalid OR used → same response
                if not row or row[2] is not None:
                    raise HTTPException(
                        status_code=400,
                        detail="Redeem failed. Please try another code."
                    )

                code_id, tier, _ = row

                if tier == "monthly":
                    expires_at = now + timedelta(days=30)
                elif tier == "yearly":
                    expires_at = now + timedelta(days=365)
                else:
                    expires_at = None

                cur.execute(
                    "UPDATE redeem_codes SET used_at=%s, used_by_discord_id=%s WHERE id=%s",
                    (now, discord_id, code_id),
                )

                cur.execute(
                    """
                    INSERT INTO redemptions
                    (discord_id, tier, redeemed_at, expires_at, code_hash, code_id)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    (discord_id, tier, now, expires_at, code_hash, code_id),
                )

                cur.execute(
                    """
                    INSERT INTO user_subscriptions
                    (discord_id, tier, redeemed_at, expires_at, last_code_hash)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (discord_id) DO UPDATE SET
                      tier = EXCLUDED.tier,
                      redeemed_at = EXCLUDED.redeemed_at,
                      expires_at = EXCLUDED.expires_at,
                      last_code_hash = EXCLUDED.last_code_hash
                    """,
                    (discord_id, tier, now, expires_at, code_hash),
                )

            conn.commit()

    except HTTPException:
        raise
    except Exception as e:
        print("REDEEM ERROR:", repr(e))
        raise HTTPException(status_code=500, detail="Internal server error")

    return {"ok": True, "tier": tier, "expires_at": expires_at}





@app.get("/")
async def root():
    return {"ok": True}









