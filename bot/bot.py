import os
import discord
from discord.ext import commands
import httpx
from dotenv import load_dotenv

load_dotenv()

DISCORD_TOKEN = os.getenv("DISCORD_TOKEN")
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")

intents = discord.Intents.default()
intents.message_content = True
intents.guilds = True

bot = commands.Bot(command_prefix="!", intents=intents)


@bot.event
async def on_ready():
    print(f"Bot is online as {bot.user} ({bot.user.id})")


async def check_premium(discord_id: int) -> bool:
    """Calls your backend to see if a user is premium."""
    try:
        async with httpx.AsyncClient() as client:
            res = await client.get(f"{BACKEND_URL}/api/premium/{discord_id}")
            res.raise_for_status()
            data = res.json()
            return data.get("premium", False)
    except Exception as e:
        print("Error checking premium:", e)
        return False


@bot.command()
async def premium(ctx, user: discord.User = None):
    target = user or ctx.author

    is_premium = await check_premium(target.id)

    if is_premium:
        await ctx.reply(f"✅ **{target}** is a premium user!")
    else:
        await ctx.reply(f"❌ **{target}** is not a premium user.")



bot.run(DISCORD_TOKEN)
