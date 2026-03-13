from fastapi import FastAPI
import os
import time
import uuid
import hmac
import hashlib
import base64
import urllib.parse
import requests

app = FastAPI()

MODE = os.getenv("MODE", "preview_only")
STOP_LOSS_USD = os.getenv("STOP_LOSS_USD", "330")

WEBULL_APP_KEY = os.getenv("WEBULL_APP_KEY")
WEBULL_APP_SECRET = os.getenv("WEBULL_APP_SECRET")
WEBULL_API_URL = os.getenv("WEBULL_API_URL", "https://api.webull.com")


@app.get("/")
def root():
    return {
        "status": "ok",
        "mode": MODE,
        "stop_loss_usd": STOP_LOSS_USD,
        "has_app_key": bool(WEBULL_APP_KEY),
        "has_app_secret": bool(WEBULL_APP_SECRET),
    }


def utc_timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def make_nonce() -> str:
    return uuid.uuid4().hex


def upper_md5(text: str) -> str:
    return hashlib.md5(text.encode("utf-8")).hexdigest().upper()


def build_signature(
    uri: str,
    headers_for_sig: dict,
    app_secret: str,
    body: str = ""
) -> tuple[str, str]:
    # Sort headers by key and build k=v pairs
    parts = [f"{k}={headers_for_sig[k]}" for k in sorted(headers_for_sig.keys())]
    s1 = "&".join(parts)

    if body:
        s2 = upper_md5(body)
        sign_string = f"{uri}&{s1}&{s2}"
    else:
        sign_string = f"{uri}&{s1}"

    encoded = urllib.parse.quote(sign_string, safe="-_.~").replace("%2f", "%2F")
    key = f"{app_secret}&".encode("utf-8")
    digest = hmac.new(key, encoded.encode("utf-8"), hashlib.sha1).digest()
    signature = base64.b64encode(digest).decode("utf-8")
    return signature, sign_string


def build_headers(uri: str, body: str = "") -> dict:
    timestamp = utc_timestamp()
    nonce = make_nonce()
    host = urllib.parse.urlparse(WEBULL_API_URL).netloc

    sig_headers = {
        "host": host,
        "x-app-key": WEBULL_APP_KEY,
        "x-signature-algorithm": "HMAC-SHA1",
        "x-signature-nonce": nonce,
        "x-signature-version": "1.0",
        "x-timestamp": timestamp,
    }

    signature, sign_string = build_signature(
        uri=uri,
        headers_for_sig=sig_headers,
        app_secret=WEBULL_APP_SECRET,
        body=body,
    )

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "host": host,
        "x-app-key": WEBULL_APP_KEY,
        "x-app-secret": WEBULL_APP_SECRET,
        "x-timestamp": timestamp,
        "x-signature-version": "1.0",
        "x-signature-algorithm": "HMAC-SHA1",
        "x-signature-nonce": nonce,
        "x-version": "v2",
        "x-signature": signature,
    }

    return headers, sign_string


@app.get("/webull/create-token")
def create_token():
    uri = "/openapi/auth/token/create"
    url = f"{WEBULL_API_URL}{uri}"
    headers, sign_string = build_headers(uri=uri, body="")

    try:
        r = requests.post(url, headers=headers, timeout=30)
        return {
            "url": url,
            "status_code": r.status_code,
            "response": r.text,
            "debug_sign_string": sign_string,
            "debug_headers_used": {
                "host": headers.get("host"),
                "x-app-key": headers.get("x-app-key"),
                "x-timestamp": headers.get("x-timestamp"),
                "x-signature-version": headers.get("x-signature-version"),
                "x-signature-algorithm": headers.get("x-signature-algorithm"),
                "x-signature-nonce": headers.get("x-signature-nonce"),
                "x-version": headers.get("x-version"),
            },
        }
    except Exception as e:
        return {"url": url, "error": str(e)}
