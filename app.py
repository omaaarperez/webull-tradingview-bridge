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

MODE = os.getenv("MODE", "preview_only").strip().lower()
STOP_LOSS_USD = os.getenv("STOP_LOSS_USD", "330")
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "")

WEBULL_APP_KEY = os.getenv("WEBULL_APP_KEY", "")
WEBULL_APP_SECRET = os.getenv("WEBULL_APP_SECRET", "")
WEBULL_API_URL = os.getenv("WEBULL_API_URL", "https://api.webull.com").rstrip("/")
WEBULL_ACCESS_TOKEN = os.getenv("WEBULL_ACCESS_TOKEN", "")
WEBULL_ACCOUNT_ID = os.getenv("WEBULL_ACCOUNT_ID", "")

# Optional guard so you do not accidentally send real experimental futures orders.
ALLOW_UNDOCUMENTED_FUTURES_PLACE = os.getenv("ALLOW_UNDOCUMENTED_FUTURES_PLACE", "false").strip().lower() == "true"

SYMBOL_MAP = {
    "MNQH2026": "MNQH6",
    "MGCJ2026": "MGCJ6",
    "MNQH6": "MNQH6",
    "MGCJ6": "MGCJ6",
    "MNQ1!": "MNQH6",
    "MGC1!": "MGCJ6",
}


@app.get("/")
def root():
    return {
        "status": "ok",
        "mode": MODE,
        "stop_loss_usd": STOP_LOSS_USD,
        "allow_undocumented_futures_place": ALLOW_UNDOCUMENTED_FUTURES_PLACE,
        "has_webull_token": bool(WEBULL_ACCESS_TOKEN),
        "has_account_id": bool(WEBULL_ACCOUNT_ID),
        "has_app_key": bool(WEBULL_APP_KEY),
        "has_app_secret": bool(WEBULL_APP_SECRET),
    }


def utc_timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def md5_upper(text: str) -> str:
    return hashlib.md5(text.encode("utf-8")).hexdigest().upper()


def generate_signature(uri: str, query_params: dict, body_params: dict, headers: dict, app_secret: str):
    params_dict = (query_params or {}).copy()
    params_dict.update({
        "x-app-key": headers["x-app-key"],
        "x-signature-algorithm": headers["x-signature-algorithm"],
        "x-signature-version": headers["x-signature-version"],
        "x-signature-nonce": headers["x-signature-nonce"],
        "x-timestamp": headers["x-timestamp"],
        "host": headers["host"],
    })

    sorted_params = sorted(params_dict.items())
    param_string = "&".join([f"{k}={v}" for k, v in sorted_params])

    body_json = ""
    body_md5 = ""
    if body_params:
        body_json = json.dumps(body_params, ensure_ascii=False, separators=(",", ":"))
        body_md5 = md5_upper(body_json)

    sign_string = f"{uri}&{param_string}{'&' + body_md5 if body_md5 else ''}"
    encoded_sign_string = quote(sign_string, safe="")

    secret = f"{app_secret}&"
    signature = base64.b64encode(
        hmac.new(secret.encode(), encoded_sign_string.encode(), hashlib.sha1).digest()
    ).decode("utf-8")

    return signature, sign_string, body_json


def build_headers(uri: str, query_params: dict = None, body_params: dict = None, include_token: bool = False):
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
        uri=uri,
        query_params=query_params or {},
        body_params=body_params or {},
        headers=headers,
        app_secret=WEBULL_APP_SECRET,
    )

    headers["x-signature"] = signature

    if include_token and WEBULL_ACCESS_TOKEN:
        headers["x-access-token"] = WEBULL_ACCESS_TOKEN

    return headers, sign_string, body_json


@app.get("/webull/create-token")
def create_token():
    uri = "/openapi/auth/token/create"
    url = f"{WEBULL_API_URL}{uri}"

    headers, sign_string, body_json = build_headers(
        uri=uri,
        query_params={},
        body_params={},
        include_token=False,
    )

    try:
        r = requests.post(url, headers=headers, timeout=30)
        return {
            "url": url,
            "status_code": r.status_code,
            "response": r.text,
            "debug_sign_string": sign_string,
        }
    except Exception as e:
        return {"url": url, "error": str(e)}


@app.get("/webull/check-token")
def check_token():
    uri = "/openapi/auth/token/check"
    url = f"{WEBULL_API_URL}{uri}"

    body_params = {"token": WEBULL_ACCESS_TOKEN}

    headers, sign_string, body_json = build_headers(
        uri=uri,
        query_params={},
        body_params=body_params,
        include_token=True,
    )

    try:
        r = requests.post(url, headers=headers, data=body_json, timeout=30)
        return {
            "url": url,
            "status_code": r.status_code,
            "response": r.text,
            "debug_sign_string": sign_string,
            "debug_body_json": body_json,
            "has_access_token": bool(WEBULL_ACCESS_TOKEN),
        }
    except Exception as e:
        return {"url": url, "error": str(e)}


@app.get("/webull/account-list")
def account_list():
    uri = "/openapi/account/list"
    url = f"{WEBULL_API_URL}{uri}"

    headers, sign_string, body_json = build_headers(
        uri=uri,
        query_params={},
        body_params={},
        include_token=True,
    )

    try:
        r = requests.get(url, headers=headers, timeout=30)
        return {
            "url": url,
            "status_code": r.status_code,
            "response": r.text,
            "debug_sign_string": sign_string,
        }
    except Exception as e:
        return {"url": url, "error": str(e)}


def get_positions():
    uri = "/openapi/assets/positions"
    url = f"{WEBULL_API_URL}{uri}"

    query_params = {
        "account_id": WEBULL_ACCOUNT_ID
    }

    headers, sign_string, body_json = build_headers(
        uri=uri,
        query_params=query_params,
        body_params={},
        include_token=True,
    )

    try:
        r = requests.get(url, headers=headers, params=query_params, timeout=30)
        return {
            "url": r.url,
            "status_code": r.status_code,
            "response": r.text,
            "debug_sign_string": sign_string,
        }
    except Exception as e:
        return {
            "url": url,
            "error": str(e),
        }


@app.get("/webull/positions")
def positions():
    return get_positions()


def get_position_side_for_symbol(symbol: str) -> str:
    result = get_positions()

    if result.get("status_code") != 200:
        return "UNKNOWN"

    try:
        data = json.loads(result.get("response", "[]"))
    except Exception:
        return "UNKNOWN"

    # Support either list response or wrapped object response
    if isinstance(data, dict):
        if isinstance(data.get("positions"), list):
            data = data["positions"]
        elif isinstance(data.get("data"), list):
            data = data["data"]
        else:
            data = []

    for p in data:
        pos_symbol = str(p.get("symbol", "")).upper()
        if pos_symbol != symbol.upper():
            continue

        qty_raw = p.get("position", p.get("quantity", p.get("qty", 0)))

        try:
            qty = float(qty_raw)
        except Exception:
            qty = 0.0

        if qty > 0:
            return "LONG"
        if qty < 0:
            return "SHORT"

        side_raw = str(p.get("side", "")).upper()
        if side_raw in {"LONG", "BUY"}:
            return "LONG"
        if side_raw in {"SHORT", "SELL"}:
            return "SHORT"

        return "FLAT"

    return "FLAT"


def preview_order(symbol: str, side: str, quantity: int):
    """
    Existing symbol-based futures preview path you were already using.
    This is kept for diagnosis only.
    """
    uri = "/openapi/trade/order/preview"
    url = f"{WEBULL_API_URL}{uri}"

    mapped_symbol = SYMBOL_MAP.get(symbol, symbol)

    body_params = {
        "account_id": WEBULL_ACCOUNT_ID,
        "new_orders": [
            {
                "combo_type": "NORMAL",
                "client_order_id": uuid.uuid4().hex,
                "symbol": mapped_symbol,
                "instrument_type": "FUTURES",
                "market": "US",
                "order_type": "MARKET",
                "quantity": str(quantity),
                "side": side.upper(),
                "time_in_force": "DAY",
                "entrust_type": "QTY"
            }
        ]
    }

    headers, sign_string, body_json = build_headers(
        uri=uri,
        query_params={},
        body_params=body_params,
        include_token=True,
    )

    print("PREVIEW BODY:", body_params)

    try:
        r = requests.post(url, headers=headers, data=body_json, timeout=30)
        print("PREVIEW RESPONSE:", r.text)
        return {
            "url": url,
            "status_code": r.status_code,
            "response": r.text,
            "debug_sign_string": sign_string,
            "debug_body_json": body_json,
        }
    except Exception as e:
        return {
            "url": url,
            "error": str(e),
            "debug_body_json": body_json,
        }


def place_order_symbol_payload(symbol: str, side: str, quantity: int):
    """
    Experimental only.
    This uses the same symbol-based futures payload style that is currently
    being rejected in your logs, but it lets us test from one place.
    """
    uri = "/openapi/trade/order/place"
    url = f"{WEBULL_API_URL}{uri}"

    mapped_symbol = SYMBOL_MAP.get(symbol, symbol)

    body_params = {
        "account_id": WEBULL_ACCOUNT_ID,
        "new_orders": [
            {
                "combo_type": "NORMAL",
                "client_order_id": uuid.uuid4().hex,
                "symbol": mapped_symbol,
                "instrument_type": "FUTURES",
                "market": "US",
                "order_type": "MARKET",
                "quantity": str(quantity),
                "side": side.upper(),
                "time_in_force": "DAY",
                "entrust_type": "QTY"
            }
        ]
    }

    headers, sign_string, body_json = build_headers(
        uri=uri,
        query_params={},
        body_params=body_params,
        include_token=True,
    )

    print("LIVE PLACE BODY:", body_params)

    try:
        r = requests.post(url, headers=headers, data=body_json, timeout=30)
        print("LIVE PLACE RESPONSE:", r.text)
        return {
            "url": url,
            "status_code": r.status_code,
            "response": r.text,
            "debug_sign_string": sign_string,
            "debug_body_json": body_json,
        }
    except Exception as e:
        return {
            "url": url,
            "error": str(e),
            "debug_body_json": body_json,
        }


@app.get("/webull/preview-mnq-buy")
def preview_mnq_buy():
    return preview_order("MNQH2026", "BUY", 1)


@app.get("/webull/preview-mgc-buy")
def preview_mgc_buy():
    return preview_order("MGCJ2026", "BUY", 1)


@app.get("/webull/get-instruments")
def get_instruments(symbols: str, category: str):
    """
    Official Webull instruments lookup route from docs.
    Note: official docs say only US_STOCK and US_ETF are supported here.
    """
    uri = "/openapi/instrument/list"
    url = f"{WEBULL_API_URL}{uri}"

    query_params = {
        "symbols": symbols,
        "category": category,
    }

    headers, sign_string, body_json = build_headers(
        uri=uri,
        query_params=query_params,
        body_params={},
        include_token=False,
    )

    try:
        r = requests.get(url, headers=headers, params=query_params, timeout=30)
        return {
            "url": r.url,
            "status_code": r.status_code,
            "response": r.text,
            "debug_sign_string": sign_string,
        }
    except Exception as e:
        return {"url": url, "error": str(e)}


@app.post("/webhook")
async def webhook(request: Request):
    data = await request.json()
    print("WEBHOOK RECEIVED:", data)

    if data.get("secret") != WEBHOOK_SECRET:
        return {"status": "unauthorized"}

    ticker = str(data.get("ticker", "")).strip()
    action = str(data.get("action", "")).strip().lower()
    sentiment = str(data.get("sentiment", "")).strip().lower()

    try:
        quantity = int(float(data.get("quantity", 1)))
    except Exception:
        return {"status": "error", "message": "Invalid quantity"}

    mapped_symbol = SYMBOL_MAP.get(ticker, ticker)

    if action == "buy":
        side = "BUY"
    elif action == "sell":
        side = "SELL"
    else:
        return {"status": "error", "message": f"Unsupported action: {action}"}

    print(f"MODE: {MODE}")
    print(f"TICKER: {ticker} -> {mapped_symbol}")
    print(f"ACTION: {action}, SIDE: {side}, SENTIMENT: {sentiment}, QTY: {quantity}")

    current_position = get_position_side_for_symbol(mapped_symbol)

    if current_position == "UNKNOWN":
        return {
            "status": "error",
            "message": "Could not determine current position state",
            "symbol": mapped_symbol,
        }

    if side == "BUY" and current_position == "LONG":
        return {
            "status": "ignored",
            "reason": "Already in LONG position",
            "ticker": ticker,
            "symbol": mapped_symbol,
            "action": action,
            "sentiment": sentiment,
            "current_position": current_position,
        }

    if side == "SELL" and current_position == "SHORT":
        return {
            "status": "ignored",
            "reason": "Already in SHORT position",
            "ticker": ticker,
            "symbol": mapped_symbol,
            "action": action,
            "sentiment": sentiment,
            "current_position": current_position,
        }

    if side == "SELL" and current_position == "FLAT" and sentiment in {"flat", "long"}:
        return {
            "status": "ignored",
            "reason": "SELL ignored because account is FLAT",
            "ticker": ticker,
            "symbol": mapped_symbol,
            "action": action,
            "sentiment": sentiment,
            "current_position": current_position,
        }

    if side == "BUY" and current_position == "FLAT" and sentiment == "short":
        return {
            "status": "ignored",
            "reason": "BUY ignored because account is FLAT",
            "ticker": ticker,
            "symbol": mapped_symbol,
            "action": action,
            "sentiment": sentiment,
            "current_position": current_position,
        }

    if MODE == "preview_only":
        print("PREVIEWING ORDER...")
        preview_result = preview_order(ticker, side, quantity)
        return {
            "status": "received",
            "mode": MODE,
            "ticker": ticker,
            "symbol": mapped_symbol,
            "action": action,
            "sentiment": sentiment,
            "quantity": quantity,
            "current_position": current_position,
            "preview_result": preview_result,
        }

    if MODE == "live":
        if not ALLOW_UNDOCUMENTED_FUTURES_PLACE:
            return {
                "status": "blocked",
                "mode": MODE,
                "message": (
                    "Live futures place-order is blocked intentionally. "
                    "Set ALLOW_UNDOCUMENTED_FUTURES_PLACE=true only if you want "
                    "to test the undocumented symbol-based futures place payload."
                ),
                "ticker": ticker,
                "symbol": mapped_symbol,
                "action": action,
                "sentiment": sentiment,
                "quantity": quantity,
                "current_position": current_position,
            }

        print("PLACING LIVE ORDER WITH EXPERIMENTAL FUTURES PAYLOAD...")
        place_result = place_order_symbol_payload(ticker, side, quantity)
        return {
            "status": "received",
            "mode": MODE,
            "ticker": ticker,
            "symbol": mapped_symbol,
            "action": action,
            "sentiment": sentiment,
            "quantity": quantity,
            "current_position": current_position,
            "place_result": place_result,
        }

    return {
        "status": "error",
        "message": f"Unsupported MODE: {MODE}",
    }
