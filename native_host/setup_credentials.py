"""
Interactive setup script to save Backblaze B2 credentials to Windows Credential Manager.
"""
import getpass
from credentials import save_b2_credentials, load_b2_credentials, DEFAULT_TARGET

def main():
    print("=" * 60)
    print("Incognito Tab Saver — Backblaze B2 Backup Setup")
    print("=" * 60)
    print("This stores your B2 credentials securely into Windows Credential Manager.")
    print(f"Target: {DEFAULT_TARGET}\n")

    try:
        existing = load_b2_credentials()
        print(f"Existing configuration found for bucket: '{existing.get('bucket')}'.")
        ans = input("Do you want to update it? (y/N): ").strip().lower()
        if ans != 'y':
            print("Existing configuration kept.")
            return
    except Exception:
        pass

    key_id = input("Backblaze Key ID: ").strip()
    if not key_id:
        print("Error: Key ID is required.")
        return

    app_key = getpass.getpass("Backblaze Application Key: ").strip()
    if not app_key:
        print("Error: Application Key is required.")
        return

    bucket = input("Bucket Name: ").strip()
    if not bucket:
        print("Error: Bucket Name is required.")
        return

    region = input("Region (e.g. us-west-004) [us-west-004]: ").strip() or "us-west-004"
    endpoint = input(f"S3 Endpoint URL [https://s3.{region}.backblazeb2.com]: ").strip() or f"https://s3.{region}.backblazeb2.com"
    object_key = input("Object Key Name [incognito_vault_backup.json]: ").strip() or "incognito_vault_backup.json"

    save_b2_credentials(key_id, app_key, bucket, region, endpoint, object_key)
    print("\n[SUCCESS] Credentials saved securely to Windows Credential Manager!")

if __name__ == "__main__":
    main()
