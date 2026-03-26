import os
import json
import time
import uuid
import hmac
import base64
import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import requests
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
APP_TITLE = "TradingView -> Webull Webhook"
MODE = os.getenv("MODE", "preview_only").strip().lower()  # preview_only | live

WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "").strip()

WEBULL_APP_KEY = os.getenv("WEBULL_APP_KEY", "").strip()
WEBULL_APP_SECRET = os.getenv("WEBULL_APP_SECRET", "").strip()
WEBULL_API_URL = os.getenv("WEBULL_API_URL", "https://api.webull.com").strip().rstrip("/")
WEBULL_ACCESS_TOKEN = os.getenv("WEBULL_ACCESS_TOKEN", "").strip()
WEBULL_ACCOUNT_ID = os.getenv("WEBULL_ACCOUNT_ID", "").strip()

REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "20"))
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

# Set to true if you want /webhook to reject when token is missing
REQUIRE_WEBULL_TOKEN = os.getenv("REQUIRE_WEBULL_TOKEN", "false").strip().lower() == "true"

# ─────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s | %(levelname)s | %(message)s",
)
logger = logging.getLogger(APP_TITLE)

app = FastAPI(title=APP_TITLE)


# ─────────────────────────────────────────────
# MODELS
# ─────────────────────────────────────────────
class TradingViewAlert(BaseModel):
    ticker: str
    action: str
    sentiment: str
    quantity: str | int | float = Field(default="1")
    price: str | int | float | None = None
    time: Optional[str] = None
    interval: Optional[str] = None


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────
def now_iso_z() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def mask_value(value: str, keep: int = 4) -> str:
    if not value:
        return ""
    if len(value) <= keep:
        return "*" * len(value)
    return "*" * (len(value) - keep) + value[-keep:]


def parse_qty(v: Any) -> int:
    try:
        return max(1, int(float(v)))
    except Exception:
        return 1


def parse_price(v: Any) -> Optional[float]:
    if v in (None, "", "null"):
        return None
    try:
        return float(v)
    except Exception:
        return None


def normalize_action(action: str) -> str:
    a = (action or "").strip().lower()
    if a in {"buy", "long"}:
        return "buy"
    if a in {"sell", "short"}:
        return "sell"
    if a in {"close", "flat", "flatten"}:
        return "flat"
    return a


def normalize_sentiment(sentiment: str) -> str:
    s = (sentiment or "").strip().lower()
    if s in {"long", "buy"}:
        return "long"
    if s in {"short", "sell"}:
        return "short"
    if s in {"flat", "close", "flatten"}:
        return "flat"
    return s


def normalize_futures_symbol(tv_ticker: str) -> str:
    """
    Convert TradingView-like symbols such as:
      MNQH2026 -> MNQH6
      MGCJ2026 -> MGCJ6
      CME_MINI:MNQH2026 -> MNQH6
    Leaves already-short symbols unchanged when possible.
    """
    raw = (tv_ticker or "").strip().upper()

    # remove exchange prefix if present
    if ":" in raw:
        raw = raw.split(":")[-1]

    # remove spaces
    raw = raw.replace(" ", "")

    # If it looks like root + month + 4-digit year, shorten year to last digit
    # Examples:
    # MNQH2026 -> MNQH6
    # MESM2026 -> MESM6
    if len(raw) >= 6 and raw[-4:].isdigit():
        year4 = raw[-4:]
        return raw[:-4] + year4[-1]

    return raw


def side_from_alert(action: str, sentiment: str) -> Optional[str]:
    """
    Output side for new order intent:
      buy + long  -> BUY
      sell + short -> SELL
      flat -> None
    """
    a = normalize_action(action)
    s = normalize_sentiment(sentiment)

    if a == "flat" or s == "flat":
        return None
    if a == "buy" and s == "long":
        return "BUY"
    if a == "sell" and s == "short":
        return "SELL"

    # fallback based on action only
    if a == "buy":
        return "BUY"
    if a == "sell":
        return "SELL"
    return None


def require_secret(incoming_secret: Optional[str], body_secret: Optional[str] = None) -> None:
    if not WEBHOOK_SECRET:
        logger.warning("WEBHOOK_SECRET is blank; webhook is not protected.")
        return

    candidate = (incoming_secret or "").strip()
    if not candidate and body_secret:
        candidate = body_secret.strip()

    if candidate != WEBHOOK_SECRET:
        raise HTTPException(status_code=401, detail="Invalid webhook secret")


from urllib.parse import quote

def build_webull_headers(
    method: str,
    path: str,
    body_json: Optional[str] = None,
    access_token: Optional[str] = None,
) -> Dict[str, str]:
    timestamp = now_iso_z()
    nonce = uuid.uuid4().hex

    host_value = "api.webull.com"

    headers = {
        "Content-Type": "application/json",
        "Host": host_value,
        "x-app-key": WEBULL_APP_KEY,
        "x-signature-algorithm": "HMAC-SHA1",
        "x-signature-version": "1.0",
        "x-signature-nonce": nonce,
        "x-timestamp": timestamp,
    }

    # Step 1: build sorted param string from signature headers
    params_dict = {
        "host": host_value,
        "x-app-key": WEBULL_APP_KEY,
        "x-signature-algorithm": "HMAC-SHA1",
        "x-signature-version": "1.0",
        "x-signature-nonce": nonce,
        "x-timestamp": timestamp,
    }

    sorted_params = sorted(params_dict.items())
    param_string = "&".join(f"{k}={v}" for k, v in sorted_params)

    # Step 2: md5(body) only if body exists and is non-empty
    body_md5 = ""
    if body_json:
        body_md5 = hashlib.md5(body_json.encode("utf-8")).hexdigest().upper()

    # Step 3: build sign string
    sign_string = f"{path}&{param_string}"
    if body_md5:
        sign_string += f"&{body_md5}"

    # Step 4: URL-encode sign string
    encoded_sign_string = quote(sign_string, safe="")

    # Step 5: HMAC-SHA1 with app_secret + "&"
    secret = f"{WEBULL_APP_SECRET}&"
    digest = hmac.new(
        secret.encode("utf-8"),
        encoded_sign_string.encode("utf-8"),
        hashlib.sha1,
    ).digest()

    signature = base64.b64encode(digest).decode("utf-8")
    headers["x-signature"] = signature

    if access_token:
        headers["access_token"] = access_token

    return headers


def webull_request(
    method: str,
    path: str,
    payload: Optional[Dict[str, Any]] = None,
    use_access_token: bool = False,
) -> Dict[str, Any]:
    url = f"{WEBULL_API_URL}{path}"
    body_json = json.dumps(payload, separators=(",", ":")) if payload is not None else None

    headers = build_webull_headers(
        method=method,
        path=path,
        body_json=body_json,
        access_token=WEBULL_ACCESS_TOKEN if use_access_token else None,
    )

    logger.info("Webull request: %s %s", method.upper(), path)
    if payload is not None:
        logger.info("Webull payload: %s", body_json)

    resp = requests.request(
        method=method.upper(),
        url=url,
        headers=headers,
        data=body_json,
        timeout=REQUEST_TIMEOUT,
    )

    text = resp.text
    logger.info("Webull response status: %s", resp.status_code)
    logger.info("Webull response body: %s", text)

    try:
        data = resp.json()
    except Exception:
        data = {"raw_text": text}

    return {
        "url": url,
        "status_code": resp.status_code,
        "data": data,
        "raw_text": text,
    }


# ─────────────────────────────────────────────
# WEBULL AUTH / ACCOUNT HELPERS
# ─────────────────────────────────────────────
def create_token() -> Dict[str, Any]:
    return webull_request("POST", "/openapi/auth/token/create", payload=None, use_access_token=False)


def check_token(token: str) -> Dict[str, Any]:
    return webull_request(
        "POST",
        "/openapi/auth/token/check",
        payload={"token": token},
        use_access_token=False,
    )


def list_accounts() -> Dict[str, Any]:
    return webull_request("GET", "/app/subscriptions/list", payload=None, use_access_token=False)


def preview_order(order_payload: Dict[str, Any]) -> Dict[str, Any]:
    return webull_request(
        "POST",
        "/trade/order/preview",
        payload=order_payload,
        use_access_token=False,
    )


def place_order(order_payload: Dict[str, Any]) -> Dict[str, Any]:
    return webull_request(
        "POST",
        "/trade/order/place",
        payload=order_payload,
        use_access_token=False,
    )


# ─────────────────────────────────────────────
# ORDER PAYLOAD BUILDER
# ─────────────────────────────────────────────
def build_futures_order_payload(alert: TradingViewAlert) -> Dict[str, Any]:
    """
    This is the main area you may need to tweak once we confirm
    the exact field names your Webull account expects for futures.
    """
    symbol = normalize_futures_symbol(alert.ticker)
    qty = parse_qty(alert.quantity)
    price = parse_price(alert.price)
    side = side_from_alert(alert.action, alert.sentiment)

    if not side:
        raise HTTPException(status_code=400, detail="Flat/close alert received; no new order side to place.")

    if not WEBULL_ACCOUNT_ID:
        raise HTTPException(status_code=500, detail="WEBULL_ACCOUNT_ID is not set.")

    client_order_id = uuid.uuid4().hex[:32]

    order_payload = {
        "account_id": WEBULL_ACCOUNT_ID,
        "new_orders": [
            {
                "client_order_id": client_order_id,
                "combo_type": "NORMAL",
                "instrument_type": "FUTURES",
                "symbol": symbol,
                "market": "US",
                "side": side,
                "order_type": "MARKET",
                "time_in_force": "DAY",
                "entrust_type": "QTY",
                "quantity": str(qty),
            }
        ],
    }

    # Optional: if later you want to do limit from TradingView price
    if price is not None:
        order_payload["tv_price_hint"] = price

    return order_payload


# ─────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────
@app.get("/health")
def health() -> Dict[str, Any]:
    return {
        "ok": True,
        "app": APP_TITLE,
        "mode": MODE,
        "webull_api_url": WEBULL_API_URL,
        "has_webhook_secret": bool(WEBHOOK_SECRET),
        "has_app_key": bool(WEBULL_APP_KEY),
        "has_app_secret": bool(WEBULL_APP_SECRET),
        "has_access_token": bool(WEBULL_ACCESS_TOKEN),
        "account_id_masked": mask_value(WEBULL_ACCOUNT_ID),
    }


@app.get("/debug/config")
def debug_config() -> Dict[str, Any]:
    return {
        "mode": MODE,
        "webull_api_url": WEBULL_API_URL,
        "webhook_secret_set": bool(WEBHOOK_SECRET),
        "webull_app_key_set": bool(WEBULL_APP_KEY),
        "webull_app_secret_set": bool(WEBULL_APP_SECRET),
        "webull_access_token_set": bool(WEBULL_ACCESS_TOKEN),
        "webull_account_id_masked": mask_value(WEBULL_ACCOUNT_ID),
        "require_webull_token": REQUIRE_WEBULL_TOKEN,
    }


@app.post("/debug/webull/create-token")
def debug_create_token(x_webhook_secret: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    require_secret(x_webhook_secret)
    return create_token()


@app.post("/debug/webull/check-token")
async def debug_check_token(
    request: Request,
    x_webhook_secret: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    require_secret(x_webhook_secret)
    body = await request.json()
    token = (body.get("token") or "").strip()
    if not token:
        raise HTTPException(status_code=400, detail="Missing token")
    return check_token(token)


@app.get("/debug/webull/accounts")
def debug_accounts(x_webhook_secret: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    require_secret(x_webhook_secret)
    if not WEBULL_ACCESS_TOKEN and REQUIRE_WEBULL_TOKEN:
        raise HTTPException(status_code=500, detail="WEBULL_ACCESS_TOKEN is missing")
    return list_accounts()


@app.post("/debug/webull/preview")
async def debug_preview(
    request: Request,
    x_webhook_secret: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    require_secret(x_webhook_secret)
    body = await request.json()
    alert = TradingViewAlert(**body)
    payload = build_futures_order_payload(alert)
    return {
        "normalized_symbol": normalize_futures_symbol(alert.ticker),
        "order_payload": payload,
        "preview_response": preview_order(payload),
    }

@app.get("/debug/webull/positions")
def debug_positions(x_webhook_secret: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    require_secret(x_webhook_secret)
    path = f"/account/positions?accountId={WEBULL_ACCOUNT_ID}"
    return webull_request("GET", path, payload=None, use_access_token=False)


@app.post("/debug/webull/place")
async def debug_place(
    request: Request,
    x_webhook_secret: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    require_secret(x_webhook_secret)
    body = await request.json()
    alert = TradingViewAlert(**body)
    payload = build_futures_order_payload(alert)
    return {
        "normalized_symbol": normalize_futures_symbol(alert.ticker),
        "order_payload": payload,
        "place_response": place_order(payload),
    }
    
@app.post("/webhook")
async def webhook(
    request: Request,
    x_webhook_secret: Optional[str] = Header(default=None),
) -> JSONResponse:
    raw_body = await request.body()

    try:
        body = json.loads(raw_body.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail="Body must be valid JSON")

    require_secret(x_webhook_secret, body.get("secret"))

    logger.info("Incoming webhook body: %s", json.dumps(body, separators=(",", ":")))

    alert = TradingViewAlert(**body)

    normalized = {
        "ticker_raw": alert.ticker,
        "ticker_normalized": normalize_futures_symbol(alert.ticker),
        "action": normalize_action(alert.action),
        "sentiment": normalize_sentiment(alert.sentiment),
        "quantity": parse_qty(alert.quantity),
        "price": parse_price(alert.price),
        "interval": alert.interval,
        "time": alert.time,
        "mode": MODE,
    }

    logger.info("Normalized alert: %s", json.dumps(normalized, separators=(",", ":")))

    # Flat/close webhook: for now just acknowledge it.
    # Later we will connect this to positions + close/reverse logic.
    if normalized["sentiment"] == "flat" or normalized["action"] == "flat":
        return JSONResponse(
            status_code=200,
            content={
                "ok": True,
                "mode": MODE,
                "message": "Flat alert received. Close logic not wired yet.",
                "normalized": normalized,
            },
        )

    if not WEBULL_ACCESS_TOKEN and REQUIRE_WEBULL_TOKEN:
        raise HTTPException(status_code=500, detail="WEBULL_ACCESS_TOKEN missing")

    order_payload = build_futures_order_payload(alert)

    if MODE == "preview_only":
        preview_resp = preview_order(order_payload)
        return JSONResponse(
            status_code=200,
            content={
                "ok": True,
                "mode": MODE,
                "normalized": normalized,
                "order_payload": order_payload,
                "webull_preview": preview_resp,
            },
        )

    if MODE == "live":
        place_resp = place_order(order_payload)
        return JSONResponse(
            status_code=200,
            content={
                "ok": True,
                "mode": MODE,
                "normalized": normalized,
                "order_payload": order_payload,
                "webull_place_order": place_resp,
            },
        )

    raise HTTPException(status_code=500, detail=f"Invalid MODE: {MODE}")


# ─────────────────────────────────────────────
# GLOBAL ERROR HANDLER
# ─────────────────────────────────────────────
@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled error: %s", str(exc))
    return JSONResponse(
        status_code=500,
        content={
            "ok": False,
            "error": str(exc),
            "path": str(request.url.path),
        },
    )
