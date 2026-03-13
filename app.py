from fastapi import FastAPI, Request
import os
import time
import uuid
import hmac
import hashlib
import base64
import json
import requests

app = FastAPI()

WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET")
MODE = os.getenv("MODE", "preview_only")
STOP_LOSS_USD = os.getenv("STOP_LOSS_USD", "330")

WEBULL_APP_KEY = os.getenv("WEBULL_APP_KEY")
WEBULL_APP_SECRET = os.getenv("WEBULL_APP_SECRET")
WEBULL_API_URL = os.getenv("WEBULL_API_URL", "https://api.webull.com")
WEBULL_ACCESS_TOKEN = os.getenv("WEBULL_ACCESS_TOKEN", "")


@app.get("/")
def root():
    return {
        "status": "ok",
        "mode": MODE,
        "stop_loss_usd": STOP_LOSS_USD,
        "has_webull_token": bool(WEBULL_ACCESS_TOKEN),
    }


def _utc_timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _nonce() -> str:
    return str(uuid.uuid4()).replace("-", "")


def _sign(secret: str, timestamp: str, nonce: str) -> str:
    # Minimal signature helper for the current auth headers flow.
    # If Webull requires a different canonical string for your endpoint,
    # we will adjust after seeing the token response.
    message = f"{timestamp}{nonce}{secret}"
    digest = hmac.new(
        secret.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha1
    ).hexdigest()
    return digest


def _base_headers(include_token: bool = False) -> dict:
    timestamp = _utc_timestamp()
    nonce = _nonce()
    signature = _sign(WEBULL_APP_SECRET, timestamp, nonce)

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "x-app-key": WEBULL_APP_KEY,
        "x-app-secret": WEBULL_APP_SECRET,
        "x-timestamp": timestamp,
        "x-signature-version": "1.0",
        "x-signature-algorithm": "HMAC-SHA1",
        "x-signature-nonce": nonce,
        "x-version": "v2",
        "x-signature": signature,
    }

    if include_token and WEBULL_ACCESS_TOKEN:
        headers["x-access-token"] = WEBULL_ACCESS_TOKEN

    return headers


@app.get("/webull/create-token")
def create_token():
    url = f"{WEBULL_API_URL}/openapi/auth/token/create"
    headers = _base_headers(include_token=False)

    try:
        r = requests.post(url, headers=headers, timeout=30)
        return {
            "url": url,
            "status_code": r.status_code,
            "response": r.text,
        }
    except Exception as e:
        return {
            "url": url,
            "error": str(e),
        }


@app.get("/webull/check-token")
def check_token():
    url = f"{WEBULL_API_URL}/openapi/auth/token/check"
    headers = _base_headers(include_token=True)

    try:
        r = requests.post(url, headers=headers, timeout=30)
        return {
            "url": url,
            "status_code": r.status_code,
            "response": r.text,
        }
    except Exception as e:
        return {
            "url": url,
            "error": str(e),
        }


@app.post("/webhook")
async def webhook(request: Request):
    data = await request.json()

    if data.get("secret") != WEBHOOK_SECRET:
        return {"status": "unauthorized"}

    return {
        "status": "received",
        "mode": MODE,
        "message": "Webhook received. Next step is Webull token creation and verification before preview orders.",
        "payload": data,
    }
