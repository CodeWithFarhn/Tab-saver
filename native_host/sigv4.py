"""
Pure Python AWS Signature Version 4 (SigV4) Signer.

Generates standard SigV4 authorization headers for S3-compatible object storage
(Backblaze B2, Cloudflare R2, AWS S3, MinIO) without external dependencies (no boto3).
Complies with Amazon S3 REST API authentication specification.
"""

import hmac
import hashlib
import datetime
import urllib.parse
from typing import Dict, Tuple, Optional


def _sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def get_signature_key(key: str, date_stamp: str, region_name: str, service_name: str) -> bytes:
    """Derive AWS SigV4 signing key."""
    k_date = _sign((b"AWS4" + key.encode("utf-8")), date_stamp)
    k_region = _sign(k_date, region_name)
    k_service = _sign(k_region, service_name)
    k_signing = _sign(k_service, "aws4_request")
    return k_signing


def sign_s3_request(
    method: str,
    url: str,
    headers: Dict[str, str],
    payload_hash: str,
    access_key: str,
    secret_key: str,
    region: str,
    service: str = "s3",
    timestamp: Optional[datetime.datetime] = None,
) -> Dict[str, str]:
    now = timestamp or datetime.datetime.now(datetime.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")

    parsed = urllib.parse.urlparse(url)
    host = parsed.netloc

    # Canonical URI: Must be strictly RFC 3986 percent-encoded; forward slashes preserved for S3
    raw_path = parsed.path or "/"
    if not raw_path.startswith("/"):
        raw_path = "/" + raw_path
    canonical_uri = urllib.parse.quote(raw_path, safe="-_.~/")

    # Canonical query string:
    # 1. Sort by parameter name (and value) in character code order (ASCII)
    # 2. URI-encode name and value using strict RFC 3986 (spaces as %20, safe='-_.~')
    # 3. Join as name=value with &
    query_params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    query_params.sort(key=lambda x: (x[0], x[1]))
    canonical_querystring = "&".join(
        f"{urllib.parse.quote(k, safe='-_.~')}={urllib.parse.quote(v, safe='-_.~')}"
        for k, v in query_params
    )

    # Prepare headers for signing
    out_headers = dict(headers)
    out_headers["Host"] = host
    out_headers["x-amz-date"] = amz_date
    out_headers["x-amz-content-sha256"] = payload_hash

    # Case-insensitive canonical headers & signed headers
    headers_lower = {k.lower(): str(v).strip() for k, v in out_headers.items()}
    header_keys = sorted(headers_lower.keys())
    canonical_headers = "".join(f"{k}:{headers_lower[k]}\n" for k in header_keys)
    signed_headers = ";".join(header_keys)

    # Canonical request
    canonical_request = (
        f"{method.upper()}\n"
        f"{canonical_uri}\n"
        f"{canonical_querystring}\n"
        f"{canonical_headers}\n"
        f"{signed_headers}\n"
        f"{payload_hash}"
    )

    # String to sign
    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = (
        f"AWS4-HMAC-SHA256\n"
        f"{amz_date}\n"
        f"{credential_scope}\n"
        f"{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"
    )

    # Derive signing key and calculate HMAC signature
    signing_key = get_signature_key(secret_key, date_stamp, region, service)
    signature = hmac.new(signing_key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    # Construct Authorization header
    authorization_header = (
        f"AWS4-HMAC-SHA256 "
        f"Credential={access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, "
        f"Signature={signature}"
    )

    out_headers["Authorization"] = authorization_header
    return out_headers


class SigV4Signer:
    """Helper class for stateful or multi-call AWS SigV4 signing."""

    def __init__(
        self,
        access_key_id: str,
        secret_access_key: str,
        region: str,
        service: str = "s3",
        endpoint: str = "",
    ):
        self.access_key = access_key_id
        self.secret_key = secret_access_key
        self.region = region
        self.service = service
        self.endpoint = endpoint

    def sign_request(
        self,
        method: str,
        uri: str,
        headers: Dict[str, str],
        payload: bytes,
    ) -> Dict[str, str]:
        """Return AWS SigV4 headers for an S3-compatible request."""
        payload_hash = hashlib.sha256(payload).hexdigest()
        if self.endpoint:
            full_url = f"{self.endpoint.rstrip('/')}/{uri.lstrip('/')}"
        else:
            full_url = f"https://s3.{self.region}.amazonaws.com/{uri.lstrip('/')}"

        return sign_s3_request(
            method=method,
            url=full_url,
            headers=headers,
            payload_hash=payload_hash,
            access_key=self.access_key,
            secret_key=self.secret_key,
            region=self.region,
            service=self.service,
        )
