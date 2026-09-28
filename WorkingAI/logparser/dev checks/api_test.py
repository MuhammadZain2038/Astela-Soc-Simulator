"""
api_test.py - standalone connectivity check for the LLM API used by
ai_scoring.py. Talks to OpenRouter directly, with no dependency on the
rest of this project, so it can tell apart:

  - a bad or missing key
  - your own account being rate-limited
  - the upstream provider (e.g. DeepSeek) being temporarily throttled
  - a local network/DNS problem

Run it directly: python api_test.py
"""

import os
import time
import requests
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("OPENROUTER_API_KEY") or os.getenv("OPEN_AI_API")
API_URL = os.getenv("API_URL", "https://openrouter.ai/api/v1/chat/completions")
MODEL_NAME = os.getenv("MODEL_NAME", "deepseek/deepseek-chat")

REQUEST_COUNT = 20
DELAY_BETWEEN_REQUESTS_SECONDS = 1


def _redact(text):
    """Removes the API key from text before it is printed."""
    text = str(text)
    return text.replace(API_KEY, "<redacted>") if API_KEY else text


def check_key_info():
    """Confirms the key is valid and shows the remaining budget, without
    spending anything - this endpoint is a plain lookup, not a completion."""
    try:
        response = requests.get(
            "https://openrouter.ai/api/v1/auth/key",
            headers={"Authorization": f"Bearer {API_KEY}"},
            timeout=10,
        )
        print("KEY INFO:", response.status_code, response.text[:400])
    except Exception as e:
        print("KEY INFO failed:", type(e).__name__, _redact(e))


def run_request_burst():
    """Sends a burst of minimal completions and prints the status code,
    timing, and any rate-limit headers for each one. A handful of 429s
    mixed with fast 200s usually means the upstream provider is briefly
    overloaded, not that your own key or usage is the problem."""
    for i in range(1, REQUEST_COUNT + 1):
        start = time.time()
        try:
            response = requests.post(
                API_URL,
                headers={"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"},
                json={
                    "model": MODEL_NAME,
                    "max_tokens": 20,
                    "messages": [{"role": "user", "content": "Reply with the word ok."}],
                },
                timeout=30,
            )
            rate_limit_headers = {
                k: v for k, v in response.headers.items()
                if "retry" in k.lower() or "ratelimit" in k.lower()
            }
            elapsed = time.time() - start
            print(f"{i:02d} {response.status_code} {elapsed:5.1f}s {rate_limit_headers} "
                  f"{_redact(response.text[:150])!r}")
        except Exception as e:
            elapsed = time.time() - start
            print(f"{i:02d} FAIL {elapsed:5.1f}s {type(e).__name__}")

        time.sleep(DELAY_BETWEEN_REQUESTS_SECONDS)


if __name__ == "__main__":
    if not API_KEY:
        print("[!] No API key found. Set OPENROUTER_API_KEY (or OPEN_AI_API) in .env.")
    else:
        check_key_info()
        run_request_burst()