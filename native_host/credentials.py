"""
Windows Credential Manager integration for Incognito Tab Saver Backup Agent.
Uses ctypes to call advapi32.dll CredReadW / CredWriteW with 0 external dependencies.
"""

import ctypes
from ctypes import wintypes
import json
from typing import Optional, Dict

CRED_TYPE_GENERIC = 1
CRED_PERSIST_LOCAL_MACHINE = 2

class CREDENTIAL(ctypes.Structure):
    _fields_ = [
        ("Flags", wintypes.DWORD),
        ("Type", wintypes.DWORD),
        ("TargetName", wintypes.LPWSTR),
        ("Comment", wintypes.LPWSTR),
        ("LastWritten", wintypes.FILETIME),
        ("CredentialBlobSize", wintypes.DWORD),
        ("CredentialBlob", ctypes.POINTER(ctypes.c_char)),
        ("Persist", wintypes.DWORD),
        ("AttributeCount", wintypes.DWORD),
        ("Attributes", ctypes.c_void_p),
        ("TargetAlias", wintypes.LPWSTR),
        ("UserName", wintypes.LPWSTR),
    ]

PCREDENTIAL = ctypes.POINTER(CREDENTIAL)

advapi32 = ctypes.WinDLL("advapi32.dll", use_last_error=True)

CredReadW = advapi32.CredReadW
CredReadW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(PCREDENTIAL)]
CredReadW.restype = wintypes.BOOL

CredWriteW = advapi32.CredWriteW
CredWriteW.argtypes = [PCREDENTIAL, wintypes.DWORD]
CredWriteW.restype = wintypes.BOOL

CredFree = advapi32.CredFree
CredFree.argtypes = [ctypes.c_void_p]
CredFree.restype = None

DEFAULT_TARGET = "IncognitoTabSaver_B2_Backup"


def save_b2_credentials(
    key_id: str,
    application_key: str,
    bucket: str,
    region: str = "us-west-004",
    endpoint: str = "",
    object_key: str = "incognito_vault_backup.json",
    target_name: str = DEFAULT_TARGET,
) -> bool:
    """Store B2 config securely into Windows Credential Manager."""
    if not endpoint:
        endpoint = f"https://s3.{region}.backblazeb2.com"

    # Auto-sanitize if accidental duplicate prefix was pasted (32 chars instead of 31 chars)
    sanitized_app_key = application_key.strip()
    if sanitized_app_key.startswith("KK00") and len(sanitized_app_key) == 32:
        sanitized_app_key = sanitized_app_key[1:]

    data = {
        "key_id": key_id.strip(),
        "application_key": sanitized_app_key,
        "bucket": bucket.strip(),
        "region": region.strip(),
        "endpoint": endpoint.strip().rstrip("/"),
        "object_key": object_key.strip().lstrip("/"),
    }

    blob_bytes = json.dumps(data).encode("utf-8")
    blob_len = len(blob_bytes)

    cred = CREDENTIAL()
    cred.Flags = 0
    cred.Type = CRED_TYPE_GENERIC
    cred.TargetName = target_name
    cred.Comment = "Backblaze B2 credentials for Incognito Tab Saver extension backup"
    cred.CredentialBlobSize = blob_len
    cred.CredentialBlob = (ctypes.c_char * blob_len).from_buffer_copy(blob_bytes)
    cred.Persist = CRED_PERSIST_LOCAL_MACHINE
    cred.UserName = data["key_id"]

    ok = CredWriteW(ctypes.byref(cred), 0)
    if not ok:
        err = ctypes.get_last_error()
        raise RuntimeError(f"CredWriteW failed with Windows error code {err}")
    return True


def load_b2_credentials(target_name: str = DEFAULT_TARGET) -> Dict[str, str]:
    """Retrieve B2 config from Windows Credential Manager."""
    p_cred = PCREDENTIAL()
    ok = CredReadW(target_name, CRED_TYPE_GENERIC, 0, ctypes.byref(p_cred))
    if not ok:
        err = ctypes.get_last_error()
        raise RuntimeError(
            f"Credential '{target_name}' not found in Windows Credential Manager (WinError {err}). "
            "Please run 'python setup_credentials.py' to save your B2 bucket credentials."
        )

    try:
        cred = p_cred.contents
        raw_blob = ctypes.string_at(cred.CredentialBlob, cred.CredentialBlobSize)
        text = raw_blob.decode("utf-8")
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                res = {k: v.strip() if isinstance(v, str) else v for k, v in data.items()}
                app_k = res.get("application_key", "")
                if app_k.startswith("KK00") and len(app_k) == 32:
                    res["application_key"] = app_k[1:]
                return res
            return data
        except json.JSONDecodeError:
            # Fallback if stored as plain application_key with username as key_id
            app_k = text.strip()
            if app_k.startswith("KK00") and len(app_k) == 32:
                app_k = app_k[1:]
            return {
                "key_id": (cred.UserName or "").strip(),
                "application_key": app_k,
            }
    finally:
        CredFree(p_cred)


if __name__ == "__main__":
    import sys
    print("Testing Windows Credential Manager helper...")
    test_target = "IncognitoTabSaver_Test_Target"
    save_b2_credentials("test_id", "test_secret", "test_bucket", target_name=test_target)
    loaded = load_b2_credentials(target_name=test_target)
    assert loaded["key_id"] == "test_id"
    assert loaded["application_key"] == "test_secret"
    print("Self-test passed! Loaded:", loaded)
