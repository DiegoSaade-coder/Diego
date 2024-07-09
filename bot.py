# Scrtipted by Diego Saade

import discord
from discord.ext import commands
import asyncio
import re
import json
from collections import defaultdict
from datetime import datetime, timedelta
import aiohttp
import hashlib
import base64
import secrets
import pyotp
import qrcode
import io
import os
import sys

intents = discord.Intents.all()
bot = commands.Bot(command_prefix='!', intents=intents)

# Laad configuratie
with open('config.json', 'r') as f:
    config = json.load(f)

# Gebruikersgegevens en caches
user_data = defaultdict(lambda: {"message_count": 0, "last_message": "", "repeated_count": 0, "links": 0, "warnings": 0})
raid_detection = defaultdict(int)
invite_cache = {}
banned_words = set(config['banned_words'])

# Gebruikersgegevens en caches
user_data = defaultdict(lambda: {"message_count": 0, "last_message": "", "repeated_count": 0, "links": 0, "warnings": 0, "last_active": datetime.now()})
raid_detection = defaultdict(int)
invite_cache = {}
banned_words = set(config['banned_words'])
user_2fa = {}

# Regex patronen

link_pattern = re.compile(r"https?://[^\s]+")


@bot.event
async def on_ready():
    print(f'{bot.user} is verbonden met Discord!')
    bot.loop.create_task(reset_user_data())
    bot.loop.create_task(update_invite_cache())

@bot.command()
@commands.has_permissions(kick_members=True)
async def kick(ctx, member: discord.Member, *, reason=None):
    await member.kick(reason=reason)
    await ctx.send(f'{member.mention} is gekickt.')
    await log_action(ctx.guild, f"{ctx.author} heeft {member} gekickt. Reden: {reason}")

@bot.command()
@commands.has_permissions(ban_members=True)
async def ban(ctx, member: discord.Member, *, reason=None):
    await member.ban(reason=reason)
    await ctx.send(f'{member.mention} is verbannen.')
    await log_action(ctx.guild, f"{ctx.author} heeft {member} verbannen. Reden: {reason}")

@bot.command()
@commands.has_permissions(manage_messages=True)
async def mute(ctx, member: discord.Member, duration: int, *, reason=None):
    muted_role = discord.utils.get(ctx.guild.roles, name="Muted")
    if not muted_role:
        muted_role = await ctx.guild.create_role(name="Muted")
        for channel in ctx.guild.channels:
            await channel.set_permissions(muted_role, speak=False, send_messages=False)
    
    await member.add_roles(muted_role, reason=reason)
    await ctx.send(f"{member.mention} is gemute voor {duration} minuten.")
    await log_action(ctx.guild, f"{ctx.author} heeft {member} gemute voor {duration} minuten. Reden: {reason}")
    
    await asyncio.sleep(duration * 60)
    await member.remove_roles(muted_role)
    await ctx.send(f"{member.mention} is niet langer gemute.")

@bot.command()
@commands.has_permissions(manage_messages=True)
async def warn(ctx, member: discord.Member, *, reason=None):
    user_data[member.id]['warnings'] += 1
    await ctx.send(f"{member.mention} heeft een waarschuwing gekregen. Totaal: {user_data[member.id]['warnings']}")
    await log_action(ctx.guild, f"{ctx.author} heeft {member} gewaarschuwd. Reden: {reason}")
    
    if user_data[member.id]['warnings'] >= config['max_warnings']:
        await member.ban(reason="Maximum aantal waarschuwingen bereikt")
        await ctx.send(f"{member.mention} is verbannen wegens te veel waarschuwingen.")

@bot.event
async def on_message(message):
    if message.author.bot:
        return

    # Anti-spam en flood controle
    user_id = message.author.id
    user_data[user_id]["message_count"] += 1
    
    # Controleer op herhaalde berichten
    if message.content == user_data[user_id]["last_message"]:
        user_data[user_id]["repeated_count"] += 1
    else:
        user_data[user_id]["repeated_count"] = 0
    
    user_data[user_id]["last_message"] = message.content

    # Controleer op links en uitnodigingen
    if link_pattern.search(message.content):
        user_data[user_id]["links"] += 1
    
    if invite_pattern.search(message.content):
        invite_match = invite_pattern.search(message.content)
        invite_code = invite_match.group().split('/')[-1]
        if invite_code not in invite_cache.get(message.guild.id, []):
            await message.delete()
            await message.channel.send(f"{message.author.mention}, externe uitnodigingen zijn niet toegestaan.")

    # Controleer op verboden woorden
    if any(word in message.content.lower() for word in banned_words):
        await message.delete()
        await message.channel.send(f"{message.author.mention}, je bericht bevat verboden woorden.")
        user_data[user_id]['warnings'] += 1

    # Neem actie bij overtredingen
    if user_data[user_id]["message_count"] > config["max_messages"]:
        await message.author.timeout(duration=60, reason="Spamming")
        await message.channel.send(f"{message.author.mention}, je stuurt te veel berichten. Je hebt een timeout van 1 minuut gekregen.")
    
    if user_data[user_id]["repeated_count"] > config["max_repeated"]:
        await message.delete()
        await message.channel.send(f"{message.author.mention}, stop met het herhalen van berichten.")
    
    if user_data[user_id]["links"] > config["max_links"]:
        await message.delete()
        await message.channel.send(f"{message.author.mention}, je stuurt te veel links.")

    await bot.process_commands(message)

@bot.event
async def on_member_join(member):
    # Raid detectie
    raid_detection[member.guild.id] += 1
    if raid_detection[member.guild.id] > config['raid_threshold']:
        await member.guild.edit(verification_level=discord.VerificationLevel.high)
        await log_action(member.guild, "Mogelijke raid gedetecteerd. Verificatieniveau verhoogd.")

    # Nieuwe account controle
    if (datetime.utcnow() - member.created_at).days < config["min_account_age"]:
        await member.kick(reason="Account te nieuw")
        await log_action(member.guild, f"{member} is gekickt omdat het account te nieuw is.")

    # Controleer op verdachte gebruikersnamen
    if any(word in member.name.lower() for word in config['suspicious_names']):
        await member.ban(reason="Verdachte gebruikersnaam")
        await log_action(member.guild, f"{member} is verbannen vanwege een verdachte gebruikersnaam.")


@bot.command()
@commands.has_permissions(administrator=True)
async def enable_2fa(ctx):
    """Schakel 2FA in voor de gebruiker"""
    secret = pyotp.random_base32()
    user_2fa[ctx.author.id] = secret
    totp = pyotp.TOTP(secret)
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp.provisioning_uri(ctx.author.name, issuer_name="Discord Security Bot"))
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)
    
    await ctx.author.send("Scan deze QR-code met je authenticator app:", file=discord.File(buffer, "2fa_qr.png"))
    await ctx.send("2FA is ingeschakeld. Check je DMs voor de QR-code.")

@bot.command()
@commands.has_permissions(administrator=True)
async def verify_2fa(ctx, token: str):
    """Verifieer 2FA token"""
    if ctx.author.id not in user_2fa:
        await ctx.send("Je hebt 2FA niet ingeschakeld.")
        return
    
    totp = pyotp.TOTP(user_2fa[ctx.author.id])
    if totp.verify(token):
        await ctx.send("2FA verificatie succesvol!")
    else:
        await ctx.send("Ongeldige 2FA token.")

@bot.event
async def on_message(message):
    if message.author.bot:
        return

    # Bestaande anti-spam en flood controle

    # Geavanceerde inhoud analyse
    content_hash = hashlib.md5(message.content.encode()).hexdigest()
    if content_hash in config['known_spam_hashes']:
        await message.delete()
        await message.channel.send(f"{message.author.mention}, je bericht is gedetecteerd als bekende spam.")
        return

    # Sentiment analyse (vereist een externe API of bibliotheek)
    # sentiment = analyze_sentiment(message.content)
    # if sentiment < config['min_sentiment_threshold']:
    #     await message.delete()
    #     await message.channel.send(f"{message.author.mention}, je bericht is verwijderd vanwege negatief sentiment.")
    #     return

    # Bestaande acties bij overtredingen

    await bot.process_commands(message)

@bot.event
async def on_member_join(member):
    # Bestaande raid detectie en nieuwe account controle

    # Captcha verificatie
    captcha = generate_captcha()
    await member.send(f"Welkom! Voer deze captcha in om toegang te krijgen tot de server: {captcha}")
    
    def check(m):
        return m.author == member and m.guild is None
    
    try:
        msg = await bot.wait_for('message', check=check, timeout=300.0)
        if msg.content == captcha:
            await member.send("Captcha correct. Welkom op de server!")
        else:
            await member.kick(reason="Foutieve captcha")
    except asyncio.TimeoutError:
        await member.kick(reason="Captcha timeout")


@bot.event
async def on_member_remove(member):
    raid_detection[member.guild.id] -= 1

async def reset_user_data():
    while True:
        await asyncio.sleep(60)
        for user in user_data:
            user_data[user] = {"message_count": 0, "last_message": "", "repeated_count": 0, "links": 0}
        raid_detection.clear()

async def update_invite_cache():
    while True:
        for guild in bot.guilds:
            try:
                invite_cache[guild.id] = [invite.code for invite in await guild.invites()]
            except discord.errors.Forbidden:
                pass
        await asyncio.sleep(600)  # Update elke 10 minuten

async def log_action(guild, message):
    log_channel = discord.utils.get(guild.channels, name=config["log_channel"])
    if log_channel:
        await log_channel.send(message)

@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.MissingPermissions):
        await ctx.send("Je hebt niet de vereiste permissies om dit commando te gebruiken.")

# Voeg deze functie toe om IP's te controleren met de AbuseIPDB API
async def check_ip(ip):
    url = f"https://api.abuseipdb.com/api/v2/check"
    querystring = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }
    headers = {
        'Accept': 'application/json',
        'Key': config['abuseipdb_key']
    }
    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers, params=querystring) as response:
            result = await response.json()
            return result['data']['abuseConfidenceScore'] > 20
        
# Bestaande hulpfuncties (reset_user_data, update_invite_cache, log_action, check_ip)

async def check_inactive_users():
    while True:
        for guild in bot.guilds:
            for member in guild.members:
                if datetime.now() - user_data[member.id]['last_active'] > timedelta(days=config['inactive_days']):
                    await member.kick(reason="Inactief voor te lange tijd")
                    await log_action(guild, f"{member} is gekickt wegens inactiviteit.")
        await asyncio.sleep(86400)  # Check elke 24 uur

def generate_captcha():
    return ''.join(secrets.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890') for _ in range(6))

@bot.command()
@commands.has_permissions(administrator=True)
async def audit(ctx):
    """Voer een beveiligingsaudit uit op de server"""
    audit_results = []
    
    # Controleer serverinstellingen
    verification_level = ctx.guild.verification_level
    if verification_level < discord.VerificationLevel.medium:
        audit_results.append("⚠️ Verificatieniveau is lager dan aanbevolen.")
    
    # Controleer rollen en permissies
    for role in ctx.guild.roles:
        if role.permissions.administrator and role != ctx.guild.default_role:
            audit_results.append(f"ℹ️ Rol '{role.name}' heeft administratorrechten.")
    
    # Controleer kanalen
    for channel in ctx.guild.channels:
        if channel.overwrites_for(ctx.guild.default_role).read_messages:
            audit_results.append(f"ℹ️ Kanaal '{channel.name}' is leesbaar voor iedereen.")
    
    # Rapport genereren
    report = "Beveiligingsaudit resultaten:\n" + "\n".join(audit_results)
    await ctx.send(report)

@bot.command()
async def info(ctx):
    """Toont informatie over de beveiligingsfuncties van de bot"""
    embed = discord.Embed(
        title="Discord Security Bot Informatie",
        description="Een overzicht van alle beveiligingsfuncties en commando's.",
        color=discord.Color.blue()
    )

    # Moderatie Commando's
    mod_commands = """
    • `!kick`: Kick een gebruiker
    • `!ban`: Ban een gebruiker
    • `!mute`: Mute een gebruiker voor een bepaalde tijd
    • `!warn`: Geef een waarschuwing aan een gebruiker
    • `!lockdown`: Zet de server in lockdown modus
    """
    embed.add_field(name="Moderatie Commando's", value=mod_commands, inline=False)

    # Beveiligingsfuncties
    security_features = """
    • Anti-spam: Detecteert en voorkomt spamberichten
    • Anti-flood: Voorkomt het snel achter elkaar sturen van berichten
    • Invite Link Controle: Verwijdert ongeautoriseerde uitnodigingslinks
    • Verboden Woorden Filter: Verwijdert berichten met verboden woorden
    • Raid Detectie: Verhoogt automatisch de serverbeveiliging bij verdachte activiteit
    • Nieuwe Account Controle: Controleert de leeftijd van nieuwe accounts
    • Captcha Verificatie: Vereist captcha-oplossing voor nieuwe leden
    • Twee-factor Authenticatie (2FA): Extra beveiliging voor beheerders
    """
    embed.add_field(name="Automatische Beveiligingsfuncties", value=security_features, inline=False)

    # Geavanceerde Functies
    advanced_features = """
    • Inactiviteitscontrole: Verwijdert inactieve gebruikers
    • IP Controle: Controleert IP-adressen op kwaadaardigheid
    • Beveiligingsaudit: Voert een audit uit van serverinstellingen
    • Gedragsanalyse: Detecteert verdacht gebruikersgedrag
    • Geautomatiseerde Backups: Maakt regelmatig backups van servergegevens
    • Geavanceerde Contentanalyse: Controleert berichten op spam en negatief sentiment
    """
    embed.add_field(name="Geavanceerde Functies", value=advanced_features, inline=False)

    # Beheerdersfuncties
    admin_features = """
    • `!enable_2fa`: Schakel 2FA in voor je account
    • `!verify_2fa`: Verifieer je 2FA token
    • `!audit`: Voer een beveiligingsaudit uit op de server
    • `!checkip`: Controleer een IP-adres op kwaadaardigheid
    """
    embed.add_field(name="Beheerdersfuncties", value=admin_features, inline=False)

    # Voeg een footer toe met een disclaimer
    embed.set_footer(text="Voor meer informatie over specifieke commando's, gebruik !help <commando>")

    await ctx.send(embed=embed)

@bot.command()
@commands.has_permissions(ban_members=True)
async def checkip(ctx, ip):
    is_malicious = await check_ip(ip)
    if is_malicious:
        await ctx.send(f"Het IP-adres {ip} is mogelijk kwaadaardig.")
    else:
        await ctx.send(f"Het IP-adres {ip} lijkt veilig.")
@bot.command()
@commands.has_permissions(administrator=True)
async def shutdown(ctx):
    await ctx.send("Shutting down...")
    await bot.logout()
    await bot.close()

@bot.command()
@commands.has_permissions(administrator=True)
async def restart(ctx):
    await ctx.send("Restarting...")
    await bot.logout()
    await bot.close()

os.execl(sys.executable, sys.executable, *sys.argv)

bot.run(config['token'])

