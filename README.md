# Incognito Tab Saver

A privacy-focused browser extension and companion native host for capturing, encrypting, and restoring Incognito and Private browsing sessions on Chromium-based browsers (Google Chrome, Brave, Microsoft Edge).

All session data is encrypted at rest using AES-256-GCM with keys derived via PBKDF2-SHA256 (600,000 iterations). An optional native messaging host provides automated, zero-knowledge cloud backup and restore to Backblaze B2 (or any S3-compatible storage) using credentials stored in the OS keystore (Windows Credential Manager).

---

## Key Features

- **Zero-Knowledge Encryption**: Master passwords are never written to disk, stored in settings, or transmitted over the wire. The encryption key resides strictly in volatile extension memory while the popup is unlocked.
- **Selective & Lazy Restoration**: Reopen entire windows or individual tabs. Non-active tabs are restored in a discarded state to prevent system resource spikes when restoring large sessions.
- **Window Geometry Retention**: Preserves window size, screen coordinates, and maximized/fullscreen states across restoration.
- **Optional Native Cloud Courier**: Ephemeral Native Messaging Host automatically syncs encrypted vault snapshots to Backblaze B2 on demand without third-party Python dependencies (pure standard library).
- **Secure Credential Storage**: Cloud storage API keys are managed through the Windows Credential Manager via native Win32 APIs, keeping secrets out of configuration files and code repositories.
- **Self-Contained & Offline-Capable**: The extension works entirely offline using `chrome.storage.local`. Cloud sync is strictly opt-in.

---

## Security Model

| Component | Implementation | Notes |
| :--- | :--- | :--- |
| **Cipher** | AES-256-GCM | Authenticated symmetric encryption preventing tampering or bit-flipping. |
| **Key Derivation** | PBKDF2-SHA256 | 600,000 rounds with cryptographically secure random salt (WebCrypto API). |
| **Key Lifecycle** | Volatile Memory Only | Cleared immediately when popup closes or browser window loses focus. |
| **Cloud Payloads** | Ciphertext Only | The remote backup is strictly the encrypted JSON envelope (data, salt, IV, iterations). |
| **Cloud Keystore** | Windows Credential Manager | Stored via `advapi32.dll` (`CredWriteW` / `CredReadW`) under `IncognitoTabSaver_B2_Backup`. |
| **Cloud Signature** | AWS SigV4 | Calculated dynamically in Python using pure `hmac` and `hashlib` (no external SDKs). |

---

## Project Structure

```
incognito-tab-saver/
├── manifest.json              # Manifest V3 extension configuration
├── background.js              # Service worker handling tab restoration & NMH bridge
├── popup.html                 # Extension user interface
├── popup.js                   # Client-side vault logic, UI events, WebCrypto operations
├── popup.css                  # UI stylesheet
├── icons/                     # Extension branding icons
├── native_host/               # Optional Backblaze B2 backup courier
│   ├── host_manifest.json     # Chrome/Brave Native Messaging Host registration manifest
│   ├── register_host.ps1      # PowerShell script to register host in Windows Registry
│   ├── unregister_host.ps1    # PowerShell script to remove host from Windows Registry
│   ├── setup_credentials.py   # CLI wizard to store S3 credentials in Windows Credential Manager
│   ├── extension_backup_agent.bat # Wrapper script enforcing zero bytecode caching
│   ├── extension_backup_agent.py # Stdio uint32-LE protocol courier
│   ├── b2_client.py           # S3 PUT/GET client with exponential backoff
│   ├── sigv4.py               # Pure Python AWS Signature Version 4 implementation
│   └── credentials.py         # Win32 Credential Manager ctypes integration
└── README.md
```

---

## Installation & Setup

### 1. Load the Browser Extension

1. Clone or download this repository.
2. Open your browser and navigate to `chrome://extensions` (or `brave://extensions`).
3. Enable **Developer mode** using the toggle in the upper right corner.
4. Click **Load unpacked** and select the `incognito-tab-saver` directory.
5. In the extension card, click **Details** and enable **"Allow in Incognito"**. (Chromium requires explicit user consent to access incognito windows).

### 2. Configure Optional Cloud Backup (Windows)

The companion Python host runs on-demand to courier encrypted snapshots to your Backblaze B2 bucket.

#### Prerequisites
- Windows 10/11
- Python 3.10+ installed

#### Step A: Register the Native Messaging Host
Open PowerShell as your current user and run:

```powershell
cd "path\to\incognito-tab-saver\native_host"
.\register_host.ps1
```

This writes the native messaging manifest entry to:
- `HKCU:\Software\Google\Chrome\NativeMessagingHosts\com.incognito_tab_saver.backup_agent`
- `HKCU:\Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\com.incognito_tab_saver.backup_agent`

#### Step B: Store B2 Credentials Securely
Run the interactive setup wizard to save your bucket details into the Windows Credential Manager:

```powershell
python setup_credentials.py
```

You will be prompted for:
- **Key ID**: Your Backblaze Application Key ID.
- **Application Key**: Your Backblaze Application Key (entered securely, not displayed).
- **Bucket Name**: Name of your target B2 bucket.
- **Region**: Your B2 bucket region (e.g., `eu-central-003` or `us-west-004`).
- **Endpoint URL**: Optional override (defaults to `https://s3.<region>.backblazeb2.com`).
- **Object Key Name**: Remote filename (defaults to `incognito_vault_backup.json`).

Credentials are saved encrypted in the Windows Credential Manager under the target `IncognitoTabSaver_B2_Backup`.

---

## Usage Guide

1. **Initial Vault Setup**: On first launch, define a master password (minimum 6 characters). This initializes the PBKDF2 derivation parameters and encrypts an empty session store.
2. **Saving a Window**: Open an incognito window with desired tabs, open the extension popup, optionally assign a tag or name, and click **Save this window** (or press Enter).
3. **Restoring Sessions**: Open the popup, authenticate with your master password, and click **Restore** on any saved session.
4. **Selective Restoration**: Click **Show tabs** under any session to expand individual URLs. Uncheck tabs you do not wish to reopen, or delete specific URLs from the archive.
5. **Manual Cloud Sync**: Click **Backup to Backblaze B2** in the footer to upload the current vault state immediately.
6. **Cloud Recovery**: On a new browser or system, click **Restore from Backblaze B2** on either the Setup screen or Lock screen. Enter the password associated with that cloud backup to complete the restore.

---

## Technical Specifications

- **Browser Platform**: Chromium Manifest V3 (Chrome, Brave, Edge).
- **Cryptography**: Web Cryptography API (`crypto.subtle`), AES-GCM (256-bit key, 12-byte IV), PBKDF2-SHA256.
- **Runtime Footprint**: Native Messaging Host process is non-daemonized and ephemeral. It executes on demand for < 1 second and terminates immediately upon message completion.
- **External Dependencies**: Zero runtime pip dependencies and zero third-party Node modules. Built entirely on web standards and Python standard libraries.

---

## License

This project is released under the [MIT License](LICENSE).
