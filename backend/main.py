import os
import asyncio
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
from fastapi import UploadFile, File

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")
DATABASE_URL = os.getenv("DATABASE_URL")
REDEEM_CODE_PEPPER = os.getenv("REDEEM_CODE_PEPPER")


def get_db():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL not set")
    return psycopg.connect(DATABASE_URL, sslmode="require")


def db_user_is_active(discord_id: str):
    now = datetime.now(timezone.utc)

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT tier, expires_at
                FROM user_subscriptions
                WHERE discord_id = %s
                ORDER BY redeemed_at DESC
                LIMIT 1
                """,
                (discord_id,),
            )
            row = cur.fetchone()

    if not row:
        return False, None, None

    tier, expires = row

    # normalize tz
    if expires is not None and getattr(expires, "tzinfo", None) is None:
        expires = expires.replace(tzinfo=timezone.utc)

    if tier == "lifetime" or expires is None:
        return True, tier, None

    return (expires > now), tier, expires


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

def humanize_remaining(expires_at: datetime, now: datetime) -> str:
    secs = int((expires_at - now).total_seconds())
    if secs <= 0:
        return "expired"

    days = secs // 86400
    years = days // 365
    days %= 365
    months = days // 30
    days %= 30

    parts = []
    if years: parts.append(f"{years} year" + ("s" if years != 1 else ""))
    if months: parts.append(f"{months} month" + ("s" if months != 1 else ""))
    if not parts:
        parts.append(f"{max(1, days)} day" + ("s" if days != 1 else ""))
    return " ".join(parts)


@app.get("/api/premium/{discord_id}")
def api_premium(discord_id: str):
    """
    Bot and frontend can call this to see if a user is premium.
    """
    active, tier, expires = db_user_is_active(discord_id)
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

    discord_id = int(user["id"])  # ✅ int for DB

    active, tier, expires = db_user_is_active(discord_id)

    started_at = None
    code_used = None

    try:
        db_url = os.getenv("DATABASE_URL")
        if db_url:
            with psycopg.connect(db_url, sslmode="require") as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT tier, redeemed_at, expires_at, last_code_hash
                        FROM user_subscriptions
                        WHERE discord_id = %s
                        ORDER BY redeemed_at DESC
                        LIMIT 1
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
        "discord_id": str(discord_id),  # ✅ string for frontend display
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
    discord_id = str(user["id"])
    active, tier, expires = db_user_is_active(discord_id)

    return {
        "id": str(discord_id),
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

    discord_id = str(user["id"])
    active, tier, expires = db_user_is_active(discord_id)

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
        grant_subscription_from_webhook(str(discord_id), plan, payload)
    except Exception as e:
        print("ERROR in grant_subscription_from_webhook:", e)
        raise HTTPException(status_code=500, detail="Failed to grant subscription")

    print(f"WEBHOOK SUCCESSFULLY GRANTED {plan} TO {discord_id}")
    return {"ok": True, "message": f"Subscription granted for {discord_id} ({plan})"}

CODE_PATTERN = re.compile(r"^[A-Za-z0-9]{4}(-[A-Za-z0-9]{4}){3}$")

def lock_seconds_for_stage(stage: int) -> int:
    base = 30
    secs = base * (2 ** (stage - 1))  # 30,60,120,240...
    return min(secs, 3600)

def locked_response(retry_after: int):
    # Your frontend notification can trigger off status 429 or locked=true
    raise HTTPException(
        status_code=429,
        detail={
            "message": "Temporarily locked from redeeming. Try again later.",
            "locked": True,
            "retry_after": retry_after,
        },
        headers={"Retry-After": str(retry_after)},
    )

@app.post("/api/redeem")
def redeem_code(request: Request, body: dict = Body(...)):
    user = get_user_from_session(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not logged in")

    discord_id = str(user["id"])
    now = datetime.now(timezone.utc)

    pepper = os.getenv("REDEEM_CODE_PEPPER")
    if not pepper:
        raise HTTPException(status_code=500, detail="Server misconfigured")

    code_input = (body.get("code") or "").strip()

    try:
        with get_db() as conn:
            with conn.cursor() as cur:

                cur.execute(
                    """
                    INSERT INTO redeem_attempts (discord_id, fails, lock_until, admin_lock_until, updated_at)
                    VALUES (%s, 0, NULL, NULL, %s)
                    ON CONFLICT (discord_id) DO UPDATE SET updated_at = EXCLUDED.updated_at
                    RETURNING fails, lock_until, admin_lock_until
                    """,
                    (discord_id, now),
                )
                fails, lock_until, admin_lock_until = cur.fetchone()

                effective_lock_until = None
                if lock_until and lock_until > now:
                    effective_lock_until = lock_until
                if admin_lock_until and admin_lock_until > now:
                    if (effective_lock_until is None) or (admin_lock_until > effective_lock_until):
                        effective_lock_until = admin_lock_until
                
                if effective_lock_until:
                    retry_after = int((effective_lock_until - now).total_seconds())
                    conn.commit()
                    locked_response(retry_after)


                # Helper to record a failure (and possibly lock), then return the standard failure
                def record_fail_and_raise():
                    nonlocal fails
                    fails += 1

                    new_lock_until = None
                    retry_after = None
                    locked_now = False

                    if fails % 3 == 0:
                        stage = fails // 3
                        lock_secs = lock_seconds_for_stage(stage)
                        new_lock_until = now + timedelta(seconds=lock_secs)
                        retry_after = lock_secs
                        locked_now = True

                    cur.execute(
                        """
                        UPDATE redeem_attempts
                        SET fails=%s, lock_until=%s, updated_at=%s
                        WHERE discord_id=%s
                        """,
                        (fails, new_lock_until, now, discord_id),
                    )
                    conn.commit()

                    # If we just locked them, return the lock response so your notification fires
                    if locked_now:
                        locked_response(retry_after)

                    # Otherwise generic failure (don’t reveal whether code exists/used)
                    raise HTTPException(status_code=400, detail="Redeem failed. Please try another code.")

                # 2) Validate code input (count invalid formats as failures too)
                if not code_input:
                    record_fail_and_raise()

                code = code_input

                # Accept either dashed OR 16 raw chars, keep case exactly
                if "-" not in code:
                    if not re.fullmatch(r"^[A-Za-z0-9]{16}$", code):
                        record_fail_and_raise()
                    code = "-".join([code[i:i+4] for i in range(0, 16, 4)])

                if not CODE_PATTERN.fullmatch(code):
                    record_fail_and_raise()

                code_hash = hashlib.sha256((pepper + code).encode("utf-8")).hexdigest()

                # 3) Redeem flow (atomic + no info leak), but DO NOT raise before updating attempts
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

                if (not row) or (row[2] is not None):
                    record_fail_and_raise()

                code_id, tier, _used_at = row
                
                # --- get current subscription (must be BEFORE computing new_expires) ---
                cur.execute(
                    """
                    SELECT tier, expires_at
                    FROM user_subscriptions
                    WHERE discord_id = %s
                    FOR UPDATE
                    """,
                    (discord_id,),
                )
                sub_row = cur.fetchone()
                
                current_tier = sub_row[0] if sub_row else None
                current_expires = sub_row[1] if sub_row else None
                
                if current_expires is not None and getattr(current_expires, "tzinfo", None) is None:
                    current_expires = current_expires.replace(tzinfo=timezone.utc)
                
                base_time = now
                if current_expires is not None and current_expires > now:
                    base_time = current_expires
                
                cur.execute("SELECT COUNT(DISTINCT tier) FROM redemptions WHERE discord_id=%s", (discord_id,))
                distinct_tiers = cur.fetchone()[0] or 0
                
                if tier == "lifetime" or expires_at is None:
                    display_tier = "lifetime"
                elif distinct_tiers <= 1:
                    display_tier = tier  # show tier if only one type redeemed ever
                else:
                    display_tier = humanize_remaining(expires_at, now)  # show generic time if mixed

                
                # mark code used
                cur.execute(
                    "UPDATE redeem_codes SET used_at=%s, used_by_discord_id=%s WHERE id=%s",
                    (now, discord_id, code_id),
                )
                
                # log redemption (store resulting expiry)
                cur.execute(
                    """
                    INSERT INTO redemptions
                    (discord_id, tier, redeemed_at, expires_at, code_hash, code_id)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    (discord_id, tier, now, new_expires, code_hash, code_id),
                )
                
                # upsert subscription
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
                    (discord_id, new_tier, now, new_expires, code_hash),
                )



                # 4) Success: reset attempts
                cur.execute(
                    """
                    UPDATE redeem_attempts
                    SET fails=0, lock_until=NULL, updated_at=%s
                    WHERE discord_id=%s
                    """,
                    (now, discord_id),
                )

            conn.commit()

    except HTTPException:
        raise
    except Exception as e:
        print("REDEEM ERROR:", repr(e))
        raise HTTPException(status_code=500, detail="Internal server error")

    return {"ok": True, "tier": new_tier, "expires_at": new_expires}

async def prune_expired_subs_loop():
    while True:
        try:
            now = datetime.now(timezone.utc)
            with get_db() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        DELETE FROM user_subscriptions
                        WHERE tier != 'lifetime'
                          AND expires_at IS NOT NULL
                          AND expires_at <= %s
                        """,
                        (now,),
                    )
                conn.commit()
            print("[prune] expired subscriptions removed")
        except Exception as e:
            print("[prune] error:", repr(e))

        # sleep 24h
        await asyncio.sleep(60 * 60 * 24)

DEV_DISCORD_ID = "857932717681147954"

def require_dev(request: Request) -> int:
    user = get_user_from_session(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not logged in")
    discord_id = str(user["id"])
    if discord_id != DEV_DISCORD_ID:
        raise HTTPException(status_code=403, detail="Forbidden")
    return discord_id

@app.post("/api/admin/import-codes")
async def admin_import_codes(
    request: Request,
    tier: Literal["monthly", "yearly", "lifetime"] = Query(...),
    file: UploadFile = File(...),
):
    require_dev(request)

    pepper = os.getenv("REDEEM_CODE_PEPPER")
    if not pepper:
        raise HTTPException(status_code=500, detail="Server misconfigured")

    content = (await file.read()).decode("utf-8", errors="ignore")
    lines = [ln.strip() for ln in content.splitlines() if ln.strip()]

    inserted = 0
    skipped = 0
    bad = 0

    with get_db() as conn:
        with conn.cursor() as cur:
            for raw in lines:
                code = raw.strip()

                # allow raw 16 -> dashed
                if "-" not in code:
                    if not re.fullmatch(r"^[A-Za-z0-9]{16}$", code):
                        bad += 1
                        continue
                    code = "-".join([code[i:i+4] for i in range(0, 16, 4)])

                if not CODE_PATTERN.fullmatch(code):
                    bad += 1
                    continue

                code_hash = hashlib.sha256((pepper + code).encode("utf-8")).hexdigest()

                cur.execute(
                    """
                    INSERT INTO redeem_codes (code_hash, tier)
                    VALUES (%s, %s)
                    ON CONFLICT (code_hash) DO NOTHING
                    """,
                    (code_hash, tier),
                )
                if cur.rowcount == 1:
                    inserted += 1
                else:
                    skipped += 1

        conn.commit()

    return {"ok": True, "inserted": inserted, "skipped": skipped, "bad": bad}

@app.post("/api/admin/codes/add")
def admin_add_codes(request: Request, body: dict = Body(...)):
    require_dev(request)

    tier = (body.get("tier") or "").lower()
    codes = body.get("codes") or []
    if tier not in ("monthly", "yearly", "lifetime"):
        raise HTTPException(400, "Invalid tier")

    pepper = os.getenv("REDEEM_CODE_PEPPER")
    if not pepper:
        raise HTTPException(status_code=500, detail="Server misconfigured")

    inserted = 0
    skipped = 0
    bad = 0

    with get_db() as conn:
        with conn.cursor() as cur:
            for raw in codes:
                code = (raw or "").strip()
                if not code:
                    bad += 1
                    continue

                if "-" not in code:
                    if not re.fullmatch(r"^[A-Za-z0-9]{16}$", code):
                        bad += 1
                        continue
                    code = "-".join([code[i:i+4] for i in range(0, 16, 4)])

                if not CODE_PATTERN.fullmatch(code):
                    bad += 1
                    continue

                h = hashlib.sha256((pepper + code).encode("utf-8")).hexdigest()
                cur.execute(
                    """
                    INSERT INTO redeem_codes (code_hash, tier)
                    VALUES (%s, %s)
                    ON CONFLICT (code_hash) DO NOTHING
                    """,
                    (h, tier),
                )
                if cur.rowcount == 1:
                    inserted += 1
                else:
                    skipped += 1
        conn.commit()

    return {"ok": True, "inserted": inserted, "skipped": skipped, "bad": bad}

@app.post("/api/admin/codes/remove")
def admin_remove_code(request: Request, body: dict = Body(...)):
    require_dev(request)

    raw = (body.get("code") or "").strip()
    if not raw:
        raise HTTPException(400, "Missing code")

    pepper = os.getenv("REDEEM_CODE_PEPPER")
    if not pepper:
        raise HTTPException(status_code=500, detail="Server misconfigured")

    code = raw
    if "-" not in code:
        if not re.fullmatch(r"^[A-Za-z0-9]{16}$", code):
            raise HTTPException(400, "Invalid code format")
        code = "-".join([code[i:i+4] for i in range(0, 16, 4)])

    if not CODE_PATTERN.fullmatch(code):
        raise HTTPException(400, "Invalid code format")

    h = hashlib.sha256((pepper + code).encode("utf-8")).hexdigest()

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM redeem_codes WHERE code_hash=%s AND used_at IS NULL", (h,))
            deleted = cur.rowcount
        conn.commit()

    return {"ok": True, "deleted": deleted}

@app.get("/api/admin/premium-users")
def admin_premium_users(request: Request):
    require_dev(request)

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT discord_id, tier, redeemed_at, expires_at, last_code_hash
                FROM user_subscriptions
                ORDER BY redeemed_at DESC
                """
            )
            rows = cur.fetchall()

    def short_hash(h):
        return None if not h else f"...{str(h)[-8:]}"

    return {
        "ok": True,
        "users": [
            {
                "discord_id": str(r[0]),
                "tier": r[1],
                "redeemed_at": r[2],
                "expires_at": r[3],
                "code_used": short_hash(r[4]),
            }
            for r in rows
        ],
    }

@app.post("/api/admin/grant")
def admin_grant(request: Request, body: dict = Body(...)):
    require_dev(request)

    discord_id = str(body.get("discord_id"))
    tier = (body.get("tier") or "").lower()
    code_label = (body.get("code_used") or "MANUAL-GRANT").strip()

    if tier not in ("monthly", "yearly", "lifetime"):
        raise HTTPException(400, "Invalid tier")

    now = datetime.now(timezone.utc)

    if tier == "lifetime":
        expires = None
    elif tier == "monthly":
        expires = now + timedelta(days=30)
    else:
        expires = now + timedelta(days=365)

    # store a "code hash" label so your UI shows code used
    # (this does NOT need to be a real redeemable code)
    last_code_hash = hashlib.sha256(("ADMIN:" + code_label).encode("utf-8")).hexdigest()

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT tier, expires_at FROM user_subscriptions WHERE discord_id=%s FOR UPDATE",
                (discord_id,),
            )
            sub = cur.fetchone()
            current_tier = sub[0] if sub else None
            current_expires = sub[1] if sub else None
    
            if current_expires is not None and getattr(current_expires, "tzinfo", None) is None:
                current_expires = current_expires.replace(tzinfo=timezone.utc)
    
            base_time = now
            if current_expires is not None and current_expires > now:
                base_time = current_expires
    
            if tier == "lifetime" or current_tier == "lifetime":
                new_tier = "lifetime"
                new_expires = None
            elif tier == "monthly":
                new_tier = "monthly"
                new_expires = base_time + timedelta(days=30)
            elif tier == "yearly":
                new_tier = "yearly"
                new_expires = base_time + timedelta(days=365)
            else:
                raise HTTPException(400, "Invalid tier")
    
            cur.execute(
                """
                INSERT INTO user_subscriptions (discord_id, tier, redeemed_at, expires_at, last_code_hash)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (discord_id) DO UPDATE SET
                  tier = EXCLUDED.tier,
                  redeemed_at = EXCLUDED.redeemed_at,
                  expires_at = EXCLUDED.expires_at,
                  last_code_hash = EXCLUDED.last_code_hash
                """,
                (discord_id, new_tier, now, new_expires, last_code_hash),
            )
        conn.commit()
    
    return {"ok": True, "discord_id": discord_id, "tier": new_tier, "expires_at": new_expires}

@app.post("/api/admin/reduce")
def admin_reduce(request: Request, body: dict = Body(...)):
    require_dev(request)

    raw = str(body.get("discord_id") or "").strip()
    tier = (body.get("tier") or "").lower().strip()

    if not raw.isdigit():
        raise HTTPException(status_code=400, detail="Invalid Discord ID")
    discord_id = int(raw)

    if tier not in ("monthly", "yearly", "lifetime"):
        raise HTTPException(status_code=400, detail="Invalid tier")

    now = datetime.now(timezone.utc)

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT tier, expires_at
                FROM user_subscriptions
                WHERE discord_id = %s
                FOR UPDATE
                """,
                (discord_id,),
            )
            row = cur.fetchone()

            if not row:
                raise HTTPException(status_code=404, detail="User has no active subscription.")

            current_tier, current_expires = row

            # lifetime (or null expires) means revoke on reduce
            if current_tier == "lifetime" or current_expires is None or tier == "lifetime":
                cur.execute("DELETE FROM user_subscriptions WHERE discord_id=%s", (discord_id,))
                conn.commit()
                return {"ok": True, "message": "Reduced lifetime -> revoked subscription."}

            if getattr(current_expires, "tzinfo", None) is None:
                current_expires = current_expires.replace(tzinfo=timezone.utc)

            delta = timedelta(days=30) if tier == "monthly" else timedelta(days=365)

            new_expires = current_expires - delta

            # if reduction wipes remaining time => revoke
            if new_expires <= now:
                cur.execute("DELETE FROM user_subscriptions WHERE discord_id=%s", (discord_id,))
                conn.commit()
                return {"ok": True, "message": "Reduction exceeded remaining time -> revoked subscription."}

            # keep tier as-is; just reduce expiry
            cur.execute(
                """
                UPDATE user_subscriptions
                SET expires_at=%s, redeemed_at=%s
                WHERE discord_id=%s
                """,
                (new_expires, now, discord_id),
            )
        conn.commit()

    return {"ok": True, "message": f"Reduced {tier} from subscription.", "expires_at": new_expires}


@app.post("/api/admin/revoke")
def admin_revoke(request: Request, body: dict = Body(...)):
    require_dev(request)
    discord_id = str(body.get("discord_id"))

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM user_subscriptions WHERE discord_id=%s", (discord_id,))
            deleted = cur.rowcount
        conn.commit()

    if deleted == 0:
        raise HTTPException(status_code=404, detail="That user does not have an active subscription.")

    return {"ok": True, "deleted": deleted}


@app.post("/api/admin/lock")
def admin_lock(request: Request, body: dict = Body(...)):
    require_dev(request)

    discord_id = str(body.get("discord_id"))
    seconds = int(body.get("seconds"))
    if seconds <= 0:
        raise HTTPException(status_code=400, detail="Seconds must be > 0")

    now = datetime.now(timezone.utc)
    admin_lock_until = now + timedelta(seconds=seconds)

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO redeem_attempts (discord_id, fails, lock_until, admin_lock_until, updated_at)
                VALUES (%s, 0, NULL, %s, %s)
                ON CONFLICT (discord_id) DO UPDATE SET
                  admin_lock_until = EXCLUDED.admin_lock_until,
                  updated_at = EXCLUDED.updated_at
                RETURNING discord_id, fails, lock_until, admin_lock_until, updated_at
                """,
                (discord_id, admin_lock_until, now),
            )
            row = cur.fetchone()
        conn.commit()

    return {
        "ok": True,
        "discord_id": row[0],
        "fails": row[1],
        "lock_until": row[2],
        "admin_lock_until": row[3],
        "updated_at": row[4],
    }

@app.post("/api/admin/unlock")
def admin_unlock(request: Request, body: dict = Body(...)):
    require_dev(request)
    discord_id = str(body.get("discord_id"))

    now = datetime.now(timezone.utc)
    with get_db() as conn:
        with conn.cursor() as cur:
            # if no row OR admin lock not active -> error
            cur.execute(
                """
                SELECT admin_lock_until
                FROM redeem_attempts
                WHERE discord_id = %s
                """,
                (discord_id,),
            )
            row = cur.fetchone()
            if not row or row[0] is None:
                raise HTTPException(status_code=404, detail="That user is not in admin lockdown.")

            cur.execute(
                """
                UPDATE redeem_attempts
                SET admin_lock_until = NULL, updated_at = %s
                WHERE discord_id = %s
                """,
                (now, discord_id),
            )
        conn.commit()

    return {"ok": True}


@app.get("/api/admin/redeem-locks")
def admin_redeem_locks(request: Request):
    require_dev(request)
    now = datetime.now(timezone.utc)

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT discord_id, fails, lock_until, admin_lock_until, updated_at
                FROM redeem_attempts
                WHERE (lock_until IS NOT NULL AND lock_until > %s)
                   OR (admin_lock_until IS NOT NULL AND admin_lock_until > %s)
                ORDER BY GREATEST(
                    COALESCE(lock_until, 'epoch'::timestamptz),
                    COALESCE(admin_lock_until, 'epoch'::timestamptz)
                ) DESC
                """,
                (now, now),
            )
            rows = cur.fetchall()

    locks = []
    for discord_id, fails, lock_until, admin_lock_until, updated_at in rows:
        # effective lock = whichever ends later
        effective = None
        lock_type = None

        if lock_until and lock_until > now:
            effective = lock_until
            lock_type = "bruteforce"

        if admin_lock_until and admin_lock_until > now:
            if effective is None or admin_lock_until > effective:
                effective = admin_lock_until
                lock_type = "admin"

        locks.append({
          "discord_id": str(discord_id),
          "fails": int(fails),
          "lock_until": lock_until,
          "admin_lock_until": admin_lock_until,
          "effective_lock_until": effective,
          "lock_type": lock_type,
          "updated_at": updated_at,
        })

    return {"ok": True, "locks": locks}



@app.on_event("startup")
async def startup_tasks():
    asyncio.create_task(prune_expired_subs_loop())

@app.get("/")
async def root():
    return {"ok": True}





























