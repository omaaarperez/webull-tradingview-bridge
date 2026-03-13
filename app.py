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

    return {
        "debug_url": url,
        "payload": payload,
        "has_app_key": WEBULL_APP_KEY is not None,
        "has_app_secret": WEBULL_APP_SECRET is not None,
        "api_url": WEBULL_API_URL
    }
