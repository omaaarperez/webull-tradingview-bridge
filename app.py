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
    "MNQH2026": "MNQH2026",
    "MGCJ2026": "MGCJ2026",
}


@app.get("/")
def root():
    return {
        "status": "ok",
        "mode": MODE,
        "stop_loss_usd": STOP_LOSS_USD,
        "has_webull_token": bool(WEBULL_ACCESS_TOKEN),
        "has_account_id": bool(WEBULL_ACCOUNT_ID),
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


def preview_order(symbol: str, side: str, quantity: int):
    uri = "/openapi/trade/order/preview"
    url = f"{WEBULL_API_URL}{uri}"

    mapped_symbol = SYMBOL_MAP.get(symbol, symbol)

    body_params = {
        "account_id": WEBULL_ACCOUNT_ID,
        "orders": [
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

    r = requests.post(url, headers=headers, data=body_json, timeout=30)

    return {
        "url": url,
        "status_code": r.status_code,
        "response": r.text,
        "debug_sign_string": sign_string,
        "debug_body_json": body_json,
    }


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

    r = requests.post(url, headers=headers, data=body_json, timeout=30)
    return {
        "url": url,
        "status_code": r.status_code,
        "response": r.text,
        "debug_sign_string": sign_string,
        "debug_body_json": body_json,
        "has_access_token": bool(WEBULL_ACCESS_TOKEN),
    }


@app.get("/webull/preview-mnq-buy")
def preview_mnq_buy():
    return preview_order("MNQH2026", "BUY", 1)


@app.get("/webull/preview-mgc-buy")
def preview_mgc_buy():
    return preview_order("MGCJ2026", "BUY", 1)


@app.post("/webhook")
async def webhook(request: Request):
    data = await request.json()

    if data.get("secret") != WEBHOOK_SECRET:
        return {"status": "unauthorized"}

    ticker = data.get("ticker", "")
    action = data.get("action", "").lower()
    quantity = int(float(data.get("quantity", 1)))

    if action == "buy":
        side = "BUY"
    elif action == "sell":
        side = "SELL"
    else:
        return {"status": "error", "message": f"Unsupported action: {action}"}

    preview_result = preview_order(ticker, side, quantity)

    return {
        "status": "received",
        "mode": MODE,
        "ticker": ticker,
        "action": action,
        "quantity": quantity,
        "preview_result": preview_result,
    }
