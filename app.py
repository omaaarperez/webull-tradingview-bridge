from fastapi import FastAPI
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


@app.get("/webull/check-token")
def check_token():
    uri = "/openapi/auth/token/check"
    url = f"{WEBULL_API_URL}{uri}"

    headers, sign_string, body_json = build_headers(
        uri=uri,
        query_params={},
        body_params={},
        include_token=True,
    )

    try:
        r = requests.post(url, headers=headers, timeout=30)
        return {
            "url": url,
            "status_code": r.status_code,
            "response": r.text,
            "debug_sign_string": sign_string,
            "has_access_token": bool(WEBULL_ACCESS_TOKEN),
        }
    except Exception as e:
        return {"url": url, "error": str(e)}
