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

    while True:
        app_key = getpass.getpass("Backblaze Application Key: ").strip()
        if not app_key:
            print("Error: Application Key is required.")
            return

        if len(app_key) == 32 and app_key.startswith("KK00"):
            print("\n[WARNING] Your Application Key is 32 characters long and starts with 'KK00'.")
            print("Standard Backblaze Application Keys typically start with 'K00' (31 characters).")
            print("You may have accidentally pasted an extra leading 'K'.")
            fix = input("Would you like to trim the leading 'K' to make it 31 characters? (y/N/re-enter [r]): ").strip().lower()
            if fix == "r":
                continue
            elif fix == "y":
                app_key = app_key[1:]
                print("Trimmed leading 'K'. Using key length:", len(app_key))
                break
            else:
                print("Keeping key as entered.")
                break
        elif len(app_key) != 31:
            print(f"\n[NOTE] Key length is {len(app_key)} characters (standard B2 app keys are usually 31 characters).")
            proceed = input("Continue with this key? (Y/n/re-enter [r]): ").strip().lower()
            if proceed == "r":
                continue
            elif proceed == "n":
                return
            else:
                break
        else:
            break

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
