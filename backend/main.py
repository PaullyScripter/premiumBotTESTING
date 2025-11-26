import os
import secrets
from urllib.parse import urlencode

from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import httpx
import os
from pathlib import Path
from dotenv import load_dotenv

# Always load the .env that lives in the same folder as main.py
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID")
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET")
DISCORD_REDIRECT_URI = os.getenv("DISCORD_REDIRECT_URI")
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:8888")

print("DEBUG DISCORD_CLIENT_ID:", repr(DISCORD_CLIENT_ID))
print("DEBUG DISCORD_REDIRECT_URI:", repr(DISCORD_REDIRECT_URI))

if not DISCORD_CLIENT_ID or not DISCORD_CLIENT_SECRET or not DISCORD_REDIRECT_URI:
    print("⚠️ Set DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, DISCORD_REDIRECT_URI in .env")


app = FastAPI()

FRONTEND_ORIGINS = [
    "http://localhost:5500",              # local dev
    "https://equinoxbot.netlify.app",      # replace with your real Netlify URL
]

# allow your Netlify site to talk to this backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=FRONTEND_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# session_id -> user dict
sessions: dict[str, dict] = {}

# discord_id (int) -> True
premium_users: set[int] = set()

# order_id -> discord_id (for fake Cryptomus)
orders: dict[str, int] = {}


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
async def get_me(request: Request):
    user = get_user_from_session(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not logged in")

    discord_id = int(user["id"])
    is_premium = discord_id in premium_users

    return {
        "id": user["id"],
        "username": user["username"],
        "discriminator": user.get("discriminator"),
        "avatar_url": make_avatar_url(user),
        "premium": is_premium,
    }


@app.post("/api/create-invoice")
async def create_invoice(request: Request):
    """
    This is where you'd call Cryptomus' API.
    For now this function:
    - checks that the user is logged in
    - creates a fake order_id
    - remembers which discord_id this order belongs to
    - returns a fake payment URL
    """
    user = get_user_from_session(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not logged in")

    body = await request.json()
    plan = body.get("plan", "premium_monthly")

    discord_id = int(user["id"])
    order_id = secrets.token_hex(8)
    orders[order_id] = discord_id

    # TODO: replace this with real Cryptomus invoice call.
    fake_payment_url = f"https://example.com/fake-cryptomus-pay?order_id={order_id}&plan={plan}"

    return {"invoice_url": fake_payment_url, "order_id": order_id}


@app.post("/api/cryptomus/webhook")
async def cryptomus_webhook(payload: dict):
    """
    This simulates what Cryptomus would send you after payment.
    For a real integration you:
      - verify signature
      - read status, etc.
    For testing you can POST e.g.:
      { "order_id": "abc123", "status": "paid" }
    """
    order_id = payload.get("order_id")
    status = payload.get("status")

    if not order_id or order_id not in orders:
        raise HTTPException(status_code=400, detail="Unknown order")

    if status == "paid":
        discord_id = orders[order_id]
        premium_users.add(discord_id)
        return {"ok": True, "message": f"User {discord_id} is now premium"}

    return {"ok": True, "message": "Ignored status"}


@app.get("/api/premium/{discord_id}")
async def check_premium(discord_id: int):
    """
    Used by the bot: returns whether a given ID is premium.
    """
    return {"discord_id": discord_id, "premium": discord_id in premium_users}


@app.get("/")
async def root():
    return {"ok": True}

