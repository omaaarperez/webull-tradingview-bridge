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

MODE = os.getenv("MODE", "preview_only")
STOP_LOSS_USD = os.getenv("STOP_LOSS_USD", "330")
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "")

WEBULL_APP_KEY = os.getenv("WEBULL_APP_KEY")
WEBULL_APP_SECRET = os.getenv("WEBULL_APP_SECRET")
WEBULL_API_URL = os.getenv("WEBULL_API_URL", "https://api.webull.com")
WEBULL_ACCESS_TOKEN = os.getenv("WEBULL_ACCESS_TOKEN", "")
WEBULL_ACCOUNT_ID = os.getenv("WEBULL_ACCOUNT_ID", "")

SYMBOL_MAP = {
    "MNQH2026": "MNQH6",
    "MGCJ2026": "MGCJ6",
    "MNQ1!": "MNQH6",
    "MGC1!": "MGCJ6",
}

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
        hmac.new((app_secret + "&").encode(), encoded.encode(), hashlib.sha1).digest()
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

def preview_order(symbol, side, quantity):
    uri = "/openapi/trade/order/preview"
    url = f"{WEBULL_API_URL}{uri}"

    mapped_symbol = SYMBOL_MAP.get(symbol, symbol)

    body = {
        "account_id": WEBULL_ACCOUNT_ID,
        "new_orders": [{
            "combo_type": "NORMAL",
            "client_order_id": uuid.uuid4().hex,
            "symbol": mapped_symbol,
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
    return r.text

def place_order(symbol, side, quantity):
    uri = "/openapi/trade/order/place"
    url = f"{WEBULL_API_URL}{uri}"

    mapped_symbol = SYMBOL_MAP.get(symbol, symbol)

    body = {
        "account_id": WEBULL_ACCOUNT_ID,
        "new_orders": [{
            "combo_type": "NORMAL",
            "client_order_id": uuid.uuid4().hex,
            "symbol": mapped_symbol,
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

@app.post("/webhook")
async def webhook(request: Request):
    data = await request.json()
    print("WEBHOOK RECEIVED:", data)

    if data.get("secret") != WEBHOOK_SECRET:
        return {"status": "unauthorized"}

    ticker = data.get("ticker")
    action = data.get("action", "").lower()
    quantity = int(float(data.get("quantity", 1)))

    side = "BUY" if action == "buy" else "SELL"

    print("MODE:", MODE)

    if MODE == "preview_only":
        result = preview_order(ticker, side, quantity)
        return {"mode": "preview", "result": result}

    # 🔥 LIVE MODE
    result = place_order(ticker, side, quantity)

    return {
        "mode": "live",
        "result": result
    }
