import os
import secrets
from urllib.parse import urlencode

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


# Always load the .env that lives in the same folder as main.py
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID")
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET")
DISCORD_REDIRECT_URI = os.getenv("DISCORD_REDIRECT_URI")
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:8888")


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




SELLAUTH_PRODUCT_MAP = {
    "monthly":  {"productId": 535940, "variantId": 818373},
    "yearly":   {"productId": 535940, "variantId": 818374},
    "lifetime": {"productId": 535940, "variantId": 818375},
}

@app.post("/api/sellauth/checkout")
async def sellauth_create_checkout(request: Request, body: dict = Body(...)):
    """
    Creates a SellAuth checkout for the logged-in Discord user.

    Body: { "plan": "monthly" | "yearly" | "lifetime" }
    Returns: { "url": "<checkout url>" }
    """
    if not SELLAUTH_API_KEY or not SELLAUTH_SHOP_ID:
        raise HTTPException(status_code=500, detail="SellAuth not configured")

    user = get_user_from_session(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not logged in")

    plan = (body.get("plan") or "").lower()
    if plan not in SELLAUTH_PRODUCT_MAP:
        raise HTTPException(status_code=400, detail="Invalid plan")

    mapping = SELLAUTH_PRODUCT_MAP[plan]

    payload = {
        "cart": [
            {
                "productId": mapping["productId"],
                "variantId": mapping["variantId"],
                "quantity": 1,
            }
        ],
        # 👇 THIS is where we send Discord user id & plan to SellAuth
        "metadata": {
            "discord_id": user["id"],  # from the Discord login session
            "plan": plan,
        },
    }

    async with httpx.AsyncClient() as client:
        res = await client.post(
            f"https://api.sellauth.com/v1/shops/{SELLAUTH_SHOP_ID}/checkout",
            headers={
                "Authorization": f"Bearer {SELLAUTH_API_KEY}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=20,
        )

    if res.status_code >= 400:
        print("SELLAUTH CHECKOUT ERROR:", res.status_code, res.text)
        raise HTTPException(status_code=500, detail="Failed to create SellAuth checkout")

    data = res.json()
    # adjust if their response uses a different field name
    checkout_url = data.get("url") or data.get("checkoutUrl") or data.get("checkout_url")
    if not checkout_url:
        raise HTTPException(status_code=500, detail="SellAuth did not return a URL")

    return {"url": checkout_url}

@app.post("/api/sellauth/delivery")
async def sellauth_dynamic_delivery(request: Request, token: str = Query("")):
    if token != SELLAUTH_WEBHOOK_SECRET:
        raise HTTPException(status_code=401, detail="Invalid token")

    raw_body = await request.body()
    data = json.loads(raw_body.decode("utf-8"))

    status = data.get("status") or data.get("payment_status") or data.get("order_status")
    if status not in ("paid", "completed", "success"):
        return {"ok": True, "message": f"Ignored status {status}"}

    meta = data.get("metadata", {}) or data.get("custom_fields", {}) or {}
    discord_id = meta.get("discord_id") or data.get("discord_id")
    plan = meta.get("plan") or data.get("plan")

    if not discord_id or not plan:
        raise HTTPException(status_code=400, detail="Missing discord_id or plan in SellAuth payload")

    grant_subscription_from_sellauth_webhook(int(discord_id), plan, data)

    return Response(
        content="Your premium has been activated. You can close this tab.",
        media_type="text/plain",
    )






@app.get("/")
async def root():
    return {"ok": True}
