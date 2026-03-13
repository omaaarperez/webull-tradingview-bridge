from fastapi import FastAPI, Request
import os
import requests

app = FastAPI()

WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET")
MODE = os.getenv("MODE", "preview_only")
STOP_LOSS_USD = os.getenv("STOP_LOSS_USD", "330")

WEBULL_APP_KEY = os.getenv("WEBULL_APP_KEY")
WEBULL_APP_SECRET = os.getenv("WEBULL_APP_SECRET")
WEBULL_API_URL = os.getenv("WEBULL_API_URL")


@app.get("/")
def root():
    return {
        "status": "ok",
        "mode": MODE,
        "stop_loss_usd": STOP_LOSS_USD
    }


def preview_order(symbol, action, quantity):

    url = f"{WEBULL_API_URL}/openapi/trade/order/preview"

    payload = {
        "symbol": symbol,
        "side": action.upper(),
        "orderType": "MKT",
        "quantity": quantity
    }

    headers = {
        "Content-Type": "application/json",
        "app-key": WEBULL_APP_KEY,
        "app-secret": WEBULL_APP_SECRET
    }

    try:
        r = requests.post(url, json=payload, headers=headers)

        return {
            "debug_url": url,
            "status_code": r.status_code,
            "response": r.text,
            "payload_sent": payload,
            "has_app_key": WEBULL_APP_KEY is not None,
            "has_app_secret": WEBULL_APP_SECRET is not None,
            "api_url_env": WEBULL_API_URL
        }

    except Exception as e:
        return {
            "error": str(e),
            "debug_url": url,
            "payload": payload
        }


@app.post("/webhook")
async def webhook(request: Request):

    data = await request.json()

    if data.get("secret") != WEBHOOK_SECRET:
        return {"status": "unauthorized"}

    ticker = data["ticker"]
    action = data["action"]
    quantity = int(data["quantity"])

    preview_result = preview_order(ticker, action, quantity)

    return {
        "status": "received",
        "mode": MODE,
        "preview_result": preview_result
    }
