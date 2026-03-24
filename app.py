from fastapi import FastAPI, Request
import os
import time
import uuid
import hmac
import hashlib
import base64
import json
from urllib.parse import quote, urlparse
import requests

app = FastAPI()

# ─────────────────────────────────────────────
# ENV
# ─────────────────────────────────────────────
MODE = os.getenv("MODE", "preview_only").lower()
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "")

WEBULL_APP_KEY = os.getenv("WEBULL_APP_KEY")
WEBULL_APP_SECRET = os.getenv("WEBULL_APP_SECRET")
WEBULL_API_URL = os.getenv("WEBULL_API_URL", "https://api.webull.com")
WEBULL_ACCESS_TOKEN = os.getenv("WEBULL_ACCESS_TOKEN", "")
WEBULL_ACCOUNT_ID = os.getenv("WEBULL_ACCOUNT_ID", "")

# ─────────────────────────────────────────────
# SYMBOL MAP
# ─────────────────────────────────────────────
SYMBOL_MAP = {
    "MNQ1!": "MNQM6",
    "MNQM2026": "MNQM6",
    "MNQM6": "MNQM6",
}

# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────
def utc_timestamp():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

def md5_upper(text):
    return hashlib.md5(text.encode()).hexdigest().upper()

def generate_signature(uri, query_params, body_params, headers, app_secret):
    params = (query_params or {}).copy()
    params.update({
        "x-app-key": headers["x-app-key"],
        "x-signature-algorithm": headers["x-signature-algorithm"],
        "x-signature-version": headers["x-signature-version"],
        "x-signature-nonce": headers["x-signature-nonce"],
        "x-timestamp": headers["x-timestamp"],
        "host": headers["host"],
    })

    sorted_params = sorted(params.items())
    param_string = "&".join([f"{k}={v}" for k, v in sorted_params])

    body_json = json.dumps(body_params or {}, separators=(",", ":"))
    body_md5 = md5_upper(body_json) if body_params else ""

    sign_string = f"{uri}&{param_string}{'&' + body_md5 if body_md5 else ''}"
    encoded = quote(sign_string, safe="")

    signature = base64.b64encode(
        hmac.new((WEBULL_APP_SECRET + "&").encode(), encoded.encode(), hashlib.sha1).digest()
    ).decode()

    return signature, sign_string, body_json

def build_headers(uri, query_params=None, body_params=None, include_token=False):
    host = urlparse(WEBULL_API_URL).netloc

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "host": host,
        "x-app-key": WEBULL_APP_KEY,
        "x-signature-algorithm": "HMAC-SHA1",
        "x-signature-version": "1.0",
        "x-signature-nonce": uuid.uuid4().hex,
        "x-timestamp": utc_timestamp(),
        "x-version": "v2",
    }

    signature, sign_string, body_json = generate_signature(
        uri, query_params or {}, body_params or {}, headers, WEBULL_APP_SECRET
    )

    headers["x-signature"] = signature

    if include_token:
        headers["x-access-token"] = WEBULL_ACCESS_TOKEN

    return headers, sign_string, body_json

# ─────────────────────────────────────────────
# POSITIONS
# ─────────────────────────────────────────────
def get_positions():
    uri = "/openapi/assets/positions"
    url = f"{WEBULL_API_URL}{uri}"

    params = {"account_id": WEBULL_ACCOUNT_ID}

    headers, _, _ = build_headers(uri, params, {}, True)

    r = requests.get(url, headers=headers, params=params)
    return r.json()

def get_position_side(symbol):
    try:
        data = get_positions()
        for p in data:
            if p.get("symbol") == symbol:
                qty = float(p.get("position", 0))
                if qty > 0:
                    return "LONG"
                if qty < 0:
                    return "SHORT"
        return "FLAT"
    except:
        return "UNKNOWN"

# ─────────────────────────────────────────────
# PREVIEW
# ─────────────────────────────────────────────
def preview_order(symbol, side, quantity):
    uri = "/openapi/trade/order/preview"
    url = f"{WEBULL_API_URL}{uri}"

    symbol = SYMBOL_MAP.get(symbol, symbol)

    body = {
        "account_id": WEBULL_ACCOUNT_ID,
        "new_orders": [{
            "combo_type": "NORMAL",
            "client_order_id": uuid.uuid4().hex,
            "symbol": symbol,
            "instrument_type": "FUTURES",
            "market": "US",
            "order_type": "MARKET",
            "quantity": str(quantity),
            "side": side,
            "time_in_force": "DAY",
            "entrust_type": "QTY"
        }]
    }

    headers, _, body_json = build_headers(uri, {}, body, True)

    r = requests.post(url, headers=headers, data=body_json)

    print("🧪 PREVIEW RESPONSE:", r.text)

    return r.text

# ─────────────────────────────────────────────
# PLACE ORDER (LIVE)
# ─────────────────────────────────────────────
def place_order(symbol, side, quantity):
    uri = "/openapi/trade/order/place"
    url = f"{WEBULL_API_URL}{uri}"

    symbol = SYMBOL_MAP.get(symbol, symbol)

    body = {
        "account_id": WEBULL_ACCOUNT_ID,
        "new_orders": [{
            "combo_type": "NORMAL",
            "client_order_id": uuid.uuid4().hex,
            "symbol": symbol,
            "instrument_type": "FUTURES",
            "market": "US",
            "order_type": "MARKET",
            "quantity": str(quantity),
            "side": side,
            "time_in_force": "DAY",
            "entrust_type": "QTY"
        }]
    }

    headers, _, body_json = build_headers(uri, {}, body, True)

    print("🚀 PLACING ORDER:", body)

    r = requests.post(url, headers=headers, data=body_json)

    print("📩 WEBULL RESPONSE:", r.text)

    return r.text

# ─────────────────────────────────────────────
# FUTURES SNAPSHOT (FIXED)
# ─────────────────────────────────────────────
@app.get("/webull/futures-snapshot")
def futures_snapshot(symbol: str = "MNQM6"):
    uri = "/openapi/market-data/futures/snapshot"
    url = f"{WEBULL_API_URL}{uri}"

    params = {
        "symbols": symbol,
        "category": "US_FUTURES"
    }

    headers, _, _ = build_headers(uri, params, {}, True)

    r = requests.get(url, headers=headers, params=params)

    print("🔍 SNAPSHOT:", r.text)

    return r.text

# ─────────────────────────────────────────────
# WEBHOOK
# ─────────────────────────────────────────────
@app.post("/webhook")
async def webhook(request: Request):
    data = await request.json()
    print("WEBHOOK RECEIVED:", data)

    if data.get("secret") != WEBHOOK_SECRET:
        return {"status": "unauthorized"}

    ticker = data.get("ticker")
    action = data.get("action", "").lower()
    quantity = int(float(data.get("quantity", 1)))

    symbol = SYMBOL_MAP.get(ticker, ticker)

    side = "BUY" if action == "buy" else "SELL"

    position = get_position_side(symbol)

    print("MODE:", MODE)

    if MODE == "preview_only":
        print("PREVIEWING ORDER...")
        result = preview_order(symbol, side, quantity)
        return {"mode": "preview", "result": result}

    if MODE == "live":
        print("PLACING LIVE ORDER...")
        result = place_order(symbol, side, quantity)
        return {"mode": "live", "result": result}

    return {"status": "error"}
