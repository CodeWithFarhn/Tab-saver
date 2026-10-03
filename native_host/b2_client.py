"""
B2 S3-compatible client using pure Python standard library http.client and SigV4.
"""

import http.client
import hashlib
import time
from typing import Dict, Any, Union
from credentials import load_b2_credentials
import sigv4

EMPTY_PAYLOAD_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def b2_push(data: Union[str, bytes]) -> Dict[str, Any]:
    """Upload encrypted vault blob to B2 using SigV4 and Virtual-Hosted-Style addressing."""
    creds = load_b2_credentials()
    payload = data.encode("utf-8") if isinstance(data, str) else data
    payload_hash = hashlib.sha256(payload).hexdigest()

    bucket = creds["bucket"]
    object_key = creds.get("object_key", "incognito_vault_backup.json").lstrip("/")
    region = creds.get("region", "eu-central-003")

    # Virtual-Hosted Style: bucket.s3.region.backblazeb2.com
    host = f"{bucket}.s3.{region}.backblazeb2.com"
    path = f"/{object_key}"
    full_url = f"https://{host}{path}"

    headers = {
        "Host": host,
        "Content-Type": "application/json",
        "Content-Length": str(len(payload)),
    }

    signed_headers = sigv4.sign_s3_request(
        method="PUT",
        url=full_url,
        headers=headers,
        payload_hash=payload_hash,
        access_key=creds["key_id"],
        secret_key=creds["application_key"],
        region=region,
        service="s3",
    )

    last_err = None
    for attempt in range(3):
        try:
            conn = http.client.HTTPSConnection(host, timeout=30)
            conn.request("PUT", path, body=payload, headers=signed_headers)
            resp = conn.getresponse()
            resp_data = resp.read()
            conn.close()

            if resp.status in (200, 204):
                return {
                    "status": "ok",
                    "bytes": len(payload),
                    "timestamp": time.time(),
                }
            else:
                body_preview = resp_data.decode("utf-8", errors="replace")
                return {
                    "status": "error",
                    "error": f"HTTP {resp.status}: {resp.reason} - {body_preview[:200]}",
                }
        except Exception as e:
            last_err = e
            if attempt < 2:
                time.sleep(1.0)

    return {
        "status": "error",
        "error": str(last_err),
    }


def b2_pull() -> Dict[str, Any]:
    """Fetch latest encrypted vault blob from B2 using SigV4 and Virtual-Hosted-Style addressing."""
    creds = load_b2_credentials()
    bucket = creds["bucket"]
    object_key = creds.get("object_key", "incognito_vault_backup.json").lstrip("/")
    region = creds.get("region", "eu-central-003")

    host = f"{bucket}.s3.{region}.backblazeb2.com"
    path = f"/{object_key}"
    full_url = f"https://{host}{path}"

    headers = {
        "Host": host,
    }

    signed_headers = sigv4.sign_s3_request(
        method="GET",
        url=full_url,
        headers=headers,
        payload_hash=EMPTY_PAYLOAD_SHA256,
        access_key=creds["key_id"],
        secret_key=creds["application_key"],
        region=region,
        service="s3",
    )

    last_err = None
    for attempt in range(3):
        try:
            conn = http.client.HTTPSConnection(host, timeout=30)
            conn.request("GET", path, headers=signed_headers)

            resp = conn.getresponse()
            resp_data = resp.read()
            conn.close()

            if resp.status == 200:
                return {
                    "status": "ok",
                    "data": resp_data.decode("utf-8"),
                    "timestamp": time.time(),
                }
            else:
                body_preview = resp_data.decode("utf-8", errors="replace")
                return {
                    "status": "error",
                    "error": f"HTTP {resp.status}: {resp.reason} - {body_preview[:200]}",
                }
        except Exception as e:
            last_err = e
            if attempt < 2:
                time.sleep(1.0)

    return {
        "status": "error",
        "error": str(last_err),
    }
