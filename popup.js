const VAULT_KEY = "vault"; // { salt, iv, data, iterations } — base64 strings, holds encrypted sessions array
const PBKDF2_ITERATIONS = 600000; // OWASP-recommended baseline for PBKDF2-SHA256
const DEFAULT_LEGACY_ITERATIONS = 250000; // used for vaults saved before the iteration count was stored
const LARGE_SESSION_WARNING_THRESHOLD = 40;

const ICONS = {
  shieldCheck: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>`,
  fingerprint: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 10a2 2 0 0 0-2 2c0 1.02-.1 2.51-.26 4"/><path d="M14 13.12c0 2.38 0 6.38-1 8.88"/><path d="M17.29 21.02c.12-.6.43-2.3.5-3.02"/><path d="M2 12a10 10 0 0 1 18-6"/><path d="M2 16h.01"/><path d="M21.8 16c.2-2 .131-5.354 0-6"/><path d="M5 19.5C5.5 18 6 15 6 12a6 6 0 0 1 .34-2"/><path d="M8.65 22c.21-.66.45-1.32.57-2"/><path d="M9 6.8a6 6 0 0 1 9 5.2v2"/></svg>`,
  lock: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>`,
  lockKeyhole: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="16" r="1"/><rect x="3" y="10" width="18" height="12" rx="2"/><path d="M7 10V7a5 5 0 0 1 10 0v3"/></svg>`,
  unlock: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/></svg>`,
  keyRound: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 18v3c0 .6.4 1 1 1h4v-3h3v-3h2l1.4-1.4a6.5 6.5 0 1 0-4-4Z"/><circle cx="16.5" cy="7.5" r=".5" fill="currentColor"/></svg>`,
  alertTriangle: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
  check: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>`,
  checkCircle: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>`,
  chevronRight: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>`,
  eye: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></svg>`,
  eyeOff: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9.88 9.88a3 3 0 1 0 4.24 4.24"/><path d="M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68"/><path d="M6.61 6.61A13.526 13.526 0 0 0 2 12s3 7 10 7a9.74 9.74 0 0 0 5.39-1.61"/><line x1="2" y1="2" x2="22" y2="22"/></svg>`,
  pencil: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 3a2.85 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5Z"/><path d="m15 5 4 4"/></svg>`,
  trash2: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18"/><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/></svg>`,
  globe: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>`,
  upload: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>`,
  download: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>`,
  archive: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="20" height="5" x="2" y="3" rx="1"/><path d="M4 8v11a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8"/><path d="M10 12h4"/></svg>`,
  x: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 6 6 18"/><path d="m6 6 12 12"/></svg>`,
  fileKey: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2v4a2 2 0 0 0 2 2h4"/><path d="M4 7V4a2 2 0 0 1 2-2h8.5L20 7.5V20a2 2 0 0 1-2 2h-6"/><circle cx="4" cy="16" r="2"/><path d="m10 10-4.5 4.5"/><path d="m9 11 1 1"/></svg>`,
  cloudUpload: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 14.899A7 7 0 1 1 15.71 8h1.79a4.5 4.5 0 0 1 2.5 8.242"/><path d="M12 12v9"/><path d="m16 16-4-4-4 4"/></svg>`,
  cloudDownload: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 14.899A7 7 0 1 1 15.71 8h1.79a4.5 4.5 0 0 1 2.5 8.242"/><path d="M12 12v9"/><path d="m8 17 4 4 4-4"/></svg>`,
  search: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>`,
};

const el = {
  toastBanner: document.getElementById("toast-banner"),
  toastIcon: document.getElementById("toast-icon"),
  toastMessage: document.getElementById("toast-message"),

  headerBrandMark: document.getElementById("header-brand-mark"),
  headerLockBtn: document.getElementById("header-lock-btn"),
  setupScreen: document.getElementById("setup-screen"),
  setupHeroIcon: document.getElementById("setup-hero-icon"),
  setupHeadingIcon: document.getElementById("setup-heading-icon"),
  setupPassword: document.getElementById("setup-password"),
  setupPasswordConfirm: document.getElementById("setup-password-confirm"),
  toggleSetupPw: document.getElementById("toggle-setup-pw"),
  toggleSetupConfirmPw: document.getElementById("toggle-setup-confirm-pw"),
  setupWarningIcon: document.getElementById("setup-warning-icon"),
  setupBtn: document.getElementById("setup-btn"),
  setupStatus: document.getElementById("setup-status"),
  importTriggerSetup: document.getElementById("import-trigger-setup"),
  importSetupIcon: document.getElementById("import-setup-icon"),
  cloudRestoreSetup: document.getElementById("cloud-restore-setup"),
  cloudRestoreSetupIcon: document.getElementById("cloud-restore-setup-icon"),

  lockScreen: document.getElementById("lock-screen"),
  lockHeroIcon: document.getElementById("lock-hero-icon"),
  unlockForm: document.getElementById("unlock-form"),
  unlockPassword: document.getElementById("unlock-password"),
  toggleUnlockPw: document.getElementById("toggle-unlock-pw"),
  unlockBtn: document.getElementById("unlock-btn"),
  unlockBtnIcon: document.getElementById("unlock-btn-icon"),
  unlockStatus: document.getElementById("unlock-status"),
  resetLink: document.getElementById("reset-link"),
  importTriggerLock: document.getElementById("import-trigger-lock"),
  cloudRestoreLock: document.getElementById("cloud-restore-lock"),
  resetConfirmPanel: document.getElementById("reset-confirm-panel"),
  resetAlertIcon: document.getElementById("reset-alert-icon"),
  cancelResetBtn: document.getElementById("cancel-reset-btn"),
  confirmResetBtn: document.getElementById("confirm-reset-btn"),
  trustStripIcon: document.getElementById("trust-strip-icon"),

  mainContent: document.getElementById("main-content"),
  permissionAlert: document.getElementById("permission-alert"),
  permissionAlertIcon: document.getElementById("permission-alert-icon"),
  allowIncognitoBtn: document.getElementById("allow-incognito-btn"),
  saveSection: document.getElementById("save-section"),
  contextBadgeIcon: document.getElementById("context-badge-icon"),
  tabCount: document.getElementById("tab-count"),
  sessionNameInput: document.getElementById("session-name-input"),
  tagInput: document.getElementById("tag-input"),
  saveBtn: document.getElementById("save-btn"),
  saveStatus: document.getElementById("save-status"),
  notIncognito: document.getElementById("not-incognito"),
  standardStateIcon: document.getElementById("standard-state-icon"),
  sessionsHeading: document.getElementById("sessions-heading"),
  exportBtn: document.getElementById("export-btn"),
  cloudPushBtn: document.getElementById("cloud-push-btn"),
  importTriggerMain: document.getElementById("import-trigger-main"),
  toolbarLockBtn: document.getElementById("toolbar-lock-btn"),
  backupHelpModal: document.getElementById("backup-help-modal"),
  helpNoteIcon: document.getElementById("help-note-icon"),
  closeHelpBtn: document.getElementById("close-help-btn"),

  searchBarWrap: document.getElementById("search-bar-wrap"),
  sessionSearchInput: document.getElementById("session-search-input"),
  clearSearchBtn: document.getElementById("clear-search-btn"),
  searchIcon: document.getElementById("search-icon"),

  sessionsList: document.getElementById("sessions-list"),
  emptyState: document.getElementById("empty-state"),
  emptyStateIcon: document.getElementById("empty-state-icon"),
  footerLockIcon: document.getElementById("footer-lock-icon"),
  backupHelpBtn: document.getElementById("backup-help-btn"),
  importInput: document.getElementById("import-input"),
};

let currentWindow = null;
let currentTabs = [];
let cryptoKey = null; // AES-GCM CryptoKey, lives only for popup lifetime

// ---------- toast notifications ----------

let toastTimer = null;
function showToast(message, type = "info", duration = 3500) {
  if (!el.toastBanner || !el.toastMessage) return;
  el.toastMessage.textContent = message;

  el.toastBanner.classList.remove("toast-success", "toast-error");
  if (type === "success") {
    el.toastBanner.classList.add("toast-success");
    if (el.toastIcon) el.toastIcon.innerHTML = ICONS.checkCircle;
  } else if (type === "error") {
    el.toastBanner.classList.add("toast-error");
    if (el.toastIcon) el.toastIcon.innerHTML = ICONS.alertTriangle;
  } else {
    if (el.toastIcon) el.toastIcon.innerHTML = ICONS.shieldCheck;
  }

  el.toastBanner.classList.remove("hidden");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    el.toastBanner.classList.add("hidden");
  }, duration);
}

// ---------- populate static icons ----------

function populateIcons() {
  if (el.headerBrandMark) el.headerBrandMark.innerHTML = ICONS.shieldCheck;
  if (el.headerLockBtn) el.headerLockBtn.innerHTML = ICONS.lockKeyhole;
  if (el.setupHeroIcon) el.setupHeroIcon.innerHTML = ICONS.fingerprint;
  if (el.setupHeadingIcon) el.setupHeadingIcon.innerHTML = ICONS.keyRound;
  if (el.toggleSetupPw) el.toggleSetupPw.innerHTML = ICONS.eye;
  if (el.toggleSetupConfirmPw) el.toggleSetupConfirmPw.innerHTML = ICONS.eye;
  if (el.setupWarningIcon) el.setupWarningIcon.innerHTML = ICONS.alertTriangle;
  if (el.importSetupIcon) el.importSetupIcon.innerHTML = ICONS.upload;
  if (el.cloudRestoreSetupIcon) el.cloudRestoreSetupIcon.innerHTML = ICONS.cloudDownload;
  if (el.cloudPushBtn) el.cloudPushBtn.innerHTML = ICONS.cloudUpload;
  if (el.lockHeroIcon) el.lockHeroIcon.innerHTML = ICONS.lock;
  if (el.toggleUnlockPw) el.toggleUnlockPw.innerHTML = ICONS.eye;
  if (el.unlockBtnIcon) el.unlockBtnIcon.innerHTML = ICONS.unlock;
  if (el.resetAlertIcon) el.resetAlertIcon.innerHTML = ICONS.alertTriangle;
  if (el.trustStripIcon) el.trustStripIcon.innerHTML = ICONS.checkCircle;
  if (el.permissionAlertIcon) el.permissionAlertIcon.innerHTML = ICONS.shieldCheck;
  if (el.contextBadgeIcon) el.contextBadgeIcon.innerHTML = ICONS.fingerprint;
  if (el.standardStateIcon) el.standardStateIcon.innerHTML = ICONS.globe;
  if (el.exportBtn) el.exportBtn.innerHTML = ICONS.download;
  if (el.importTriggerMain) el.importTriggerMain.innerHTML = ICONS.upload;
  if (el.toolbarLockBtn) el.toolbarLockBtn.innerHTML = ICONS.lockKeyhole;
  if (el.helpNoteIcon) el.helpNoteIcon.innerHTML = ICONS.fileKey;
  if (el.emptyStateIcon) el.emptyStateIcon.innerHTML = ICONS.archive;
  if (el.footerLockIcon) el.footerLockIcon.innerHTML = ICONS.lockKeyhole;
  if (el.searchIcon) el.searchIcon.innerHTML = ICONS.search;
}

// ---------- crypto helpers ----------

function bufToB64(buf) {
  const bytes = new Uint8Array(buf);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i += 8192) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + 8192));
  }
  return btoa(binary);
}

function b64ToBuf(b64) {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)).buffer;
}

async function deriveKey(password, saltBuf, iterations) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: saltBuf, iterations, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptSessions(sessions, key, salt, iterations) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(JSON.stringify(sessions)));
  await chrome.storage.local.set({
    [VAULT_KEY]: {
      salt: bufToB64(salt),
      iv: bufToB64(iv),
      data: bufToB64(ciphertext),
      iterations,
    },
  });
}

async function decryptVaultRaw(key, vault) {
  const dec = new TextDecoder();
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64ToBuf(vault.iv) }, key, b64ToBuf(vault.data));
  return dec.decode(plaintext);
}

function parseAndValidateSessions(jsonText) {
  const parsed = JSON.parse(jsonText);
  if (!isValidSessionsArray(parsed)) {
    throw new Error("Vault data doesn't match the expected sessions format.");
  }
  return parsed;
}

async function decryptSessions(key, vault) {
  const text = await decryptVaultRaw(key, vault);
  return parseAndValidateSessions(text);
}

function isValidSessionsArray(data) {
  if (!Array.isArray(data)) return false;
  return data.every(
    (s) =>
      s &&
      typeof s === "object" &&
      typeof s.id === "string" &&
      (typeof s.tag === "string" || typeof s.name === "string") &&
      typeof s.savedAt === "string" &&
      Array.isArray(s.tabs) &&
      s.tabs.every((t) => t && typeof t.url === "string")
  );
}

async function getVault() {
  if (typeof chrome === "undefined" || !chrome.storage?.local) return null;
  const data = await chrome.storage.local.get(VAULT_KEY);
  return data[VAULT_KEY] || null;
}

async function getSessions() {
  if (!cryptoKey) return [];
  const vault = await getVault();
  if (!vault) return [];
  try {
    return await decryptSessions(cryptoKey, vault);
  } catch (err) {
    console.error("Failed to read saved sessions:", err);
    alert(
      "Couldn't read saved session data (it may be corrupted). Nothing was changed. " +
        "If this keeps happening, use Reset on the lock screen as a last resort."
    );
    throw err;
  }
}

async function setSessions(sessions) {
  const vault = await getVault();
  const salt = b64ToBuf(vault.salt);
  const iterations = vault.iterations || DEFAULT_LEGACY_ITERATIONS;
  await encryptSessions(sessions, cryptoKey, salt, iterations);

  // Asynchronous push to Backblaze B2 via Native Messaging Agent
  chrome.runtime.sendMessage({ type: "cloudBackupPush" }, (res) => {
    if (chrome.runtime.lastError || !res?.ok) {
      const err = res?.error || chrome.runtime.lastError?.message || "Sync paused";
      console.warn("Cloud backup notice:", err);
      if (el.saveStatus) {
        el.saveStatus.textContent = "Saved locally. (Cloud backup: " + err + ")";
      }
    }
  });
}

function isAllowedIncognitoAccess() {
  return new Promise((resolve) => chrome.extension.isAllowedIncognitoAccess(resolve));
}

function isRestorableUrl(url) {
  return typeof url === "string" && /^https?:\/\//i.test(url);
}

function sanitizeFaviconUrl(url) {
  if (typeof url !== "string") return "";
  if (/^https?:\/\//i.test(url)) return url;
  // Discard massive base64 images that bloat vault size by megabytes; allow only tiny inline vectors
  if (/^data:image\//i.test(url) && url.length <= 512) return url;
  return "";
}

function formatDate(iso) {
  const d = new Date(iso);
  return d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

function getDomainOrUrl(url) {
  if (!url) return "";
  try {
    const parsed = new URL(url);
    return parsed.hostname + (parsed.pathname === "/" ? "" : parsed.pathname);
  } catch {
    return url.replace(/^https?:\/\//i, "");
  }
}

// ---------- password visibility toggles ----------

function setupPasswordToggle(btn, input) {
  if (!btn || !input) return;
  btn.addEventListener("click", () => {
    const isPw = input.type === "password";
    input.type = isPw ? "text" : "password";
    btn.innerHTML = isPw ? ICONS.eyeOff : ICONS.eye;
  });
}

setupPasswordToggle(el.toggleSetupPw, el.setupPassword);
setupPasswordToggle(el.toggleSetupConfirmPw, el.setupPasswordConfirm);
setupPasswordToggle(el.toggleUnlockPw, el.unlockPassword);

// ---------- direct "Allow in Incognito" action ----------

if (el.allowIncognitoBtn) {
  el.allowIncognitoBtn.addEventListener("click", () => {
    if (typeof chrome !== "undefined" && chrome.tabs && chrome.runtime) {
      chrome.tabs.create({ url: `chrome://extensions/?id=${chrome.runtime.id}` });
    }
  });
}

// ---------- lock vault ----------

function lockVault() {
  cryptoKey = null;
  el.mainContent.classList.add("hidden");
  el.setupScreen.classList.add("hidden");
  el.headerLockBtn.classList.add("hidden");
  el.lockScreen.classList.remove("hidden");
  el.unlockPassword.value = "";
  el.unlockStatus.textContent = "";
  el.resetConfirmPanel.classList.add("hidden");
  el.unlockPassword.focus();
}

if (el.headerLockBtn) el.headerLockBtn.addEventListener("click", lockVault);
if (el.toolbarLockBtn) el.toolbarLockBtn.addEventListener("click", lockVault);

// ---------- backup help modal ----------

if (el.backupHelpBtn && el.backupHelpModal) {
  el.backupHelpBtn.addEventListener("click", () => {
    el.backupHelpModal.classList.toggle("hidden");
  });
}
if (el.closeHelpBtn && el.backupHelpModal) {
  el.closeHelpBtn.addEventListener("click", () => {
    el.backupHelpModal.classList.add("hidden");
  });
}

// ---------- reset vault ----------

if (el.resetLink && el.resetConfirmPanel) {
  el.resetLink.addEventListener("click", () => {
    el.resetConfirmPanel.classList.remove("hidden");
  });
}

if (el.cancelResetBtn && el.resetConfirmPanel) {
  el.cancelResetBtn.addEventListener("click", () => {
    el.resetConfirmPanel.classList.add("hidden");
  });
}

if (el.confirmResetBtn) {
  el.confirmResetBtn.addEventListener("click", async () => {
    if (typeof chrome !== "undefined" && chrome.storage?.local) {
      await chrome.storage.local.remove(VAULT_KEY);
    }
    cryptoKey = null;
    el.resetConfirmPanel.classList.add("hidden");
    el.lockScreen.classList.add("hidden");
    el.setupScreen.classList.remove("hidden");
    el.setupPassword.value = "";
    el.setupPasswordConfirm.value = "";
    el.setupStatus.textContent = "";
    el.setupPassword.focus();
  });
}

// ---------- init / unlock ----------

async function init() {
  populateIcons();

  if (typeof chrome === "undefined" || !chrome.storage?.local) {
    // Standalone / demo preview mode when viewed directly in a browser
    el.mainContent.classList.remove("hidden");
    el.headerLockBtn.classList.remove("hidden");
    el.saveSection.classList.remove("hidden");
    el.tabCount.textContent = "7 open";
    const demoSessions = [
      {
        id: "demo-1",
        name: "Weekend research",
        tag: "Research",
        savedAt: new Date(Date.now() - 3600000).toISOString(),
        tabs: [
          { url: "https://longreads.com/article/question", title: "The shape of a good question", favIconUrl: "" },
          { url: "https://fieldnotes.studio/quiet-systems", title: "Notes on quiet systems", favIconUrl: "" },
          { url: "https://readwise.io/field-guide", title: "A field guide to attention", favIconUrl: "" },
        ],
      },
      {
        id: "demo-2",
        name: "Tokyo planning",
        tag: "Travel",
        savedAt: new Date(Date.now() - 86400000).toISOString(),
        tabs: [
          { url: "https://mapstr.com/tokyo-coffee", title: "Kiyosumi-shirakawa coffee map", favIconUrl: "" },
          { url: "https://japantravel.navitime.com/route", title: "Train route planner", favIconUrl: "" },
        ],
      },
    ];
    renderSessionsFromList(demoSessions);
    return;
  }

  const vault = await getVault();
  if (!vault) {
    el.setupScreen.classList.remove("hidden");
    el.setupPassword.focus();
  } else {
    el.lockScreen.classList.remove("hidden");
    el.unlockPassword.focus();
  }
}

async function unlockApp() {
  const allowed = await isAllowedIncognitoAccess();

  if (!allowed) {
    el.permissionAlert.classList.remove("hidden");
  } else {
    currentWindow = await chrome.windows.getCurrent();

    if (currentWindow.incognito) {
      currentTabs = await chrome.tabs.query({ windowId: currentWindow.id });
      const count = currentTabs.length;
      el.tabCount.textContent = `${count} open`;
      el.saveBtn.textContent = `Save ${count} tab${count === 1 ? "" : "s"}`;
      el.saveSection.classList.remove("hidden");
      el.sessionNameInput.focus();
    } else {
      el.notIncognito.classList.remove("hidden");
    }
  }

  el.setupScreen.classList.add("hidden");
  el.lockScreen.classList.add("hidden");
  el.headerLockBtn.classList.remove("hidden");
  el.mainContent.classList.remove("hidden");

  await renderSessions();
}

// ---------- setup screen ----------

el.setupBtn.addEventListener("click", attemptSetup);
el.setupPasswordConfirm.addEventListener("keydown", (e) => {
  if (e.key === "Enter") attemptSetup();
});

async function attemptSetup() {
  const pw = el.setupPassword.value;
  const confirmPw = el.setupPasswordConfirm.value;

  if (pw.length < 6) {
    el.setupStatus.textContent = "Use at least 6 characters.";
    return;
  }
  if (pw !== confirmPw) {
    el.setupStatus.textContent = "Passwords don't match.";
    return;
  }

  const salt = crypto.getRandomValues(new Uint8Array(16));
  cryptoKey = await deriveKey(pw, salt, PBKDF2_ITERATIONS);
  await encryptSessions([], cryptoKey, salt, PBKDF2_ITERATIONS);

  el.setupPassword.value = "";
  el.setupPasswordConfirm.value = "";
  await unlockApp();
}

// ---------- unlock screen ----------

if (el.unlockForm) {
  el.unlockForm.addEventListener("submit", (e) => {
    e.preventDefault();
    attemptUnlock();
  });
}

async function attemptUnlock() {
  const pw = el.unlockPassword.value;
  const vault = await getVault();
  if (!vault) return;

  const iterations = vault.iterations || DEFAULT_LEGACY_ITERATIONS;

  let key;
  let rawText;
  try {
    const salt = b64ToBuf(vault.salt);
    key = await deriveKey(pw, salt, iterations);
    rawText = await decryptVaultRaw(key, vault); // tests authentication tag
  } catch {
    el.unlockStatus.textContent = "Wrong password.";
    el.unlockPassword.select();
    return;
  }

  // Password authenticated successfully; now validate decrypted JSON payload against schema
  let sessions;
  try {
    sessions = parseAndValidateSessions(rawText);
  } catch (err) {
    console.error("Vault data validation error:", err);
    el.unlockStatus.textContent = "Password is correct, but the saved data appears corrupted.";
    return;
  }

  cryptoKey = key;

  // Seamless migration: upgrade older vaults created with fewer iterations to modern PBKDF2 iterations
  if (!vault.iterations || vault.iterations < PBKDF2_ITERATIONS) {
    try {
      const newSalt = crypto.getRandomValues(new Uint8Array(16));
      cryptoKey = await deriveKey(pw, newSalt, PBKDF2_ITERATIONS);
      await encryptSessions(sessions, cryptoKey, newSalt, PBKDF2_ITERATIONS);
    } catch (e) {
      console.warn("Vault iteration upgrade skipped:", e);
    }
  }

  el.unlockPassword.value = "";
  el.unlockStatus.textContent = "";
  await unlockApp();
}

// ---------- save session ----------

el.saveBtn.addEventListener("click", attemptSave);
el.sessionNameInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") attemptSave();
});
el.tagInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") attemptSave();
});

async function attemptSave() {
  const enteredName = el.sessionNameInput.value.trim();
  const enteredTag = el.tagInput.value.trim() || "General";
  const name = enteredName || enteredTag || "Untitled session";

  const savable = currentTabs.filter((t) => isRestorableUrl(t.url));
  const skipped = currentTabs.length - savable.length;

  const session = {
    id: crypto.randomUUID(),
    name,
    tag: enteredTag,
    savedAt: new Date().toISOString(),
    windowId: currentWindow.id,
    windowBounds: {
      width: currentWindow.width,
      height: currentWindow.height,
      left: currentWindow.left,
      top: currentWindow.top,
      state: currentWindow.state,
    },
    tabs: savable.map((t) => ({
      url: t.url,
      title: t.title,
      favIconUrl: sanitizeFaviconUrl(t.favIconUrl) || null,
      pinned: t.pinned,
    })),
  };

  let sessions;
  try {
    sessions = await getSessions();
  } catch {
    return;
  }
  sessions.unshift(session);
  await setSessions(sessions);

  el.sessionNameInput.value = "";
  el.tagInput.value = "";
  const skippedNote = skipped > 0 ? ` (${skipped} internal tab${skipped === 1 ? "" : "s"} skipped)` : "";
  setSaveStatus(`Saved "${name}" (${session.tabs.length} tabs)${skippedNote}.`, false);

  await renderSessions();
}

function setSaveStatus(text, isError) {
  if (!text) return;
  showToast(text, isError ? "error" : "success");
}

// ---------- render sessions with live search ----------

let allCachedSessions = [];

async function renderSessions() {
  let sessions;
  try {
    sessions = await getSessions();
  } catch {
    return;
  }
  allCachedSessions = sessions;
  filterAndRenderSessions();
}

function filterAndRenderSessions() {
  const query = (el.sessionSearchInput ? el.sessionSearchInput.value : "").trim().toLowerCase();
  if (el.clearSearchBtn) {
    el.clearSearchBtn.classList.toggle("hidden", !query);
  }

  const filtered = query
    ? allCachedSessions.filter((s) => {
        const nameMatch = (s.name || "").toLowerCase().includes(query);
        const tagMatch = (s.tag || "").toLowerCase().includes(query);
        const tabMatch = (s.tabs || []).some(
          (t) => (t.title || "").toLowerCase().includes(query) || (t.url || "").toLowerCase().includes(query)
        );
        return nameMatch || tagMatch || tabMatch;
      })
    : allCachedSessions;

  renderSessionsFromList(filtered, query);
}

let searchDebounceTimer = null;

if (el.sessionSearchInput) {
  el.sessionSearchInput.addEventListener("input", () => {
    clearTimeout(searchDebounceTimer);
    searchDebounceTimer = setTimeout(() => {
      filterAndRenderSessions();
    }, 100);
  });
}
if (el.clearSearchBtn) {
  el.clearSearchBtn.addEventListener("click", () => {
    clearTimeout(searchDebounceTimer);
    if (el.sessionSearchInput) el.sessionSearchInput.value = "";
    filterAndRenderSessions();
    if (el.sessionSearchInput) el.sessionSearchInput.focus();
  });
}

function renderSessionsFromList(sessions, filterQuery = "") {
  el.sessionsList.innerHTML = "";

  const total = allCachedSessions.length;
  if (el.searchBarWrap) {
    el.searchBarWrap.classList.toggle("hidden", total === 0);
  }

  if (total === 0) {
    el.sessionsHeading.textContent = "No sessions saved yet";
    el.emptyState.classList.remove("hidden");
    return;
  }

  el.emptyState.classList.add("hidden");

  if (filterQuery) {
    el.sessionsHeading.textContent = `Found ${sessions.length} of ${total} session${total === 1 ? "" : "s"}`;
  } else {
    el.sessionsHeading.textContent = `${total} saved session${total === 1 ? "" : "s"}`;
  }

  if (sessions.length === 0 && filterQuery) {
    const noResults = document.createElement("div");
    noResults.className = "empty-state";
    noResults.style.padding = "24px 12px";
    noResults.innerHTML = `
      <p class="muted" style="margin: 0;">No sessions matching "<strong>${escapeHtml(filterQuery)}</strong>"</p>
    `;
    el.sessionsList.appendChild(noResults);
    return;
  }

  // Use DocumentFragment to batch DOM insertions into a single layout reflow
  const fragment = document.createDocumentFragment();

  sessions.forEach((session, index) => {
    const sessionName = session.name || session.tag || "Untitled session";
    const sessionTag = session.tag || "Personal";

    const row = document.createElement("article");
    row.className = "session-card";
    row.dataset.id = session.id;

    const tabRowsHtml = session.tabs
      .map((t, i) => {
        const cleanDomain = getDomainOrUrl(t.url);
        return `
        <div class="tab-row selected" data-index="${i}">
          <button type="button" class="checkbox-btn checked" data-index="${i}" aria-label="Toggle tab inclusion">${ICONS.check}</button>
          <div class="tab-favicon">
            <img class="tab-favicon-img" data-src="${escapeHtml(sanitizeFaviconUrl(t.favIconUrl))}" alt="" />
          </div>
          <div class="tab-copy">
            <strong title="${escapeHtml(t.title || t.url)}">${escapeHtml(t.title || t.url)}</strong>
            <span title="${escapeHtml(t.url)}">${escapeHtml(cleanDomain)}</span>
          </div>
          <button type="button" class="icon-button tab-remove" data-index="${i}" title="Remove tab from session">${ICONS.x}</button>
        </div>`;
      })
      .join("");

    row.innerHTML = `
      <div class="session-head">
        <button type="button" class="session-summary" data-id="${session.id}" aria-expanded="false">
          <span class="chevron">${ICONS.chevronRight}</span>
          <span class="session-number mono">${String(index + 1).padStart(2, "0")}</span>
          <span class="session-title-wrap">
            <strong class="session-title-text" data-id="${session.id}">${escapeHtml(sessionName)}</strong>
            <span class="session-meta">
              <span class="session-tag-pill">${escapeHtml(sessionTag)}</span>
              <span class="meta-dot">&bull;</span>
              <span class="tab-badge">${session.tabs.length} tabs</span>
              <span class="meta-dot">&bull;</span>
              <span class="meta-date">${formatDate(session.savedAt)}</span>
            </span>
          </span>
        </button>
        <div class="session-actions">
          <button type="button" class="icon-button rename-btn" data-id="${session.id}" title="Rename session" aria-label="Rename session">${ICONS.pencil}</button>
          <button type="button" class="icon-button danger-icon delete-trigger-btn" data-id="${session.id}" title="Delete session" aria-label="Delete session">${ICONS.trash2}</button>
        </div>
      </div>

      <div class="tab-panel hidden" data-id="${session.id}">
        <div class="tab-panel-tools">
          <span class="mono selected-count-text">${session.tabs.length}/${session.tabs.length} selected</span>
          <div>
            <button type="button" class="text-button select-all-btn" data-id="${session.id}">Select all</button>
            <span>/</span>
            <button type="button" class="text-button select-none-btn" data-id="${session.id}">Clear</button>
          </div>
        </div>
        <div class="tab-list">
          ${tabRowsHtml || '<p class="muted">No tabs remain in this session.</p>'}
        </div>
        <button type="button" class="btn btn-primary restore-button" data-id="${session.id}">
          Restore ${session.tabs.length} tabs
        </button>
      </div>

      <div class="delete-confirm hidden" data-id="${session.id}">
        <div>
          <strong>Delete this saved session?</strong>
          <span>The tabs themselves will not be affected.</span>
        </div>
        <div class="confirm-actions">
          <button type="button" class="btn btn-ghost cancel-delete-btn" data-id="${session.id}">Cancel</button>
          <button type="button" class="btn btn-danger confirm-delete-btn" data-id="${session.id}">Delete</button>
        </div>
      </div>
    `;

    fragment.appendChild(row);
  });

  el.sessionsList.appendChild(fragment);

  // Attach favicons safely with fallback
  el.sessionsList.querySelectorAll(".tab-favicon-img").forEach((img) => {
    const src = img.dataset.src;
    if (!src) {
      img.style.display = "none";
      if (img.parentElement) img.parentElement.innerHTML = ICONS.globe;
      return;
    }
    img.addEventListener("error", () => {
      img.style.display = "none";
      if (img.parentElement) img.parentElement.innerHTML = ICONS.globe;
    });
    img.src = src;
  });
}

// ---------- event delegation for session cards ----------

el.sessionsList.addEventListener("click", async (e) => {
  const target = e.target;
  const sessionEl = target.closest(".session-card");
  if (!sessionEl) return;
  const sessionId = sessionEl.dataset.id;

  // Toggle Accordion Expand/Collapse
  const summaryBtn = target.closest(".session-summary");
  if (summaryBtn && !target.closest(".rename-input")) {
    const panel = sessionEl.querySelector(`.tab-panel[data-id="${sessionId}"]`);
    const chevron = summaryBtn.querySelector(".chevron");
    const isExpanded = !panel.classList.contains("hidden");
    panel.classList.toggle("hidden", isExpanded);
    chevron.classList.toggle("rotated", !isExpanded);
    summaryBtn.setAttribute("aria-expanded", String(!isExpanded));
    return;
  }

  // Restore Action
  const restoreBtn = target.closest(".restore-button");
  if (restoreBtn) {
    return restoreSession(sessionId);
  }

  // Show Delete Confirmation Panel
  const deleteTrigger = target.closest(".delete-trigger-btn");
  if (deleteTrigger) {
    const confirmPanel = sessionEl.querySelector(`.delete-confirm[data-id="${sessionId}"]`);
    if (confirmPanel) confirmPanel.classList.remove("hidden");
    return;
  }

  // Cancel Delete
  const cancelDelete = target.closest(".cancel-delete-btn");
  if (cancelDelete) {
    const confirmPanel = sessionEl.querySelector(`.delete-confirm[data-id="${sessionId}"]`);
    if (confirmPanel) confirmPanel.classList.add("hidden");
    return;
  }

  // Confirm Delete
  const confirmDelete = target.closest(".confirm-delete-btn");
  if (confirmDelete) {
    return deleteSession(sessionId);
  }

  // Inline Rename
  const renameBtn = target.closest(".rename-btn");
  if (renameBtn) {
    return toggleInlineRename(sessionEl, sessionId, renameBtn);
  }

  // Select All Tabs in Card
  const selectAll = target.closest(".select-all-btn");
  if (selectAll) {
    return setAllCheckboxes(sessionEl, sessionId, true);
  }

  // Clear / Deselect All Tabs in Card
  const selectNone = target.closest(".select-none-btn");
  if (selectNone) {
    return setAllCheckboxes(sessionEl, sessionId, false);
  }

  // Toggle Individual Tab Checkbox
  const checkboxBtn = target.closest(".checkbox-btn");
  if (checkboxBtn) {
    const tabRow = checkboxBtn.closest(".tab-row");
    const isChecked = checkboxBtn.classList.contains("checked");
    checkboxBtn.classList.toggle("checked", !isChecked);
    checkboxBtn.innerHTML = !isChecked ? ICONS.check : "";
    tabRow.classList.toggle("selected", !isChecked);
    updateSelectionCounter(sessionEl, sessionId);
    return;
  }

  // Remove Single Tab
  const removeTabBtn = target.closest(".tab-remove");
  if (removeTabBtn) {
    const tabIndex = Number(removeTabBtn.dataset.index);
    return removeTabFromSession(sessionId, tabIndex);
  }
});

function updateSelectionCounter(sessionEl, sessionId) {
  const allRows = sessionEl.querySelectorAll(".tab-row");
  const selectedRows = sessionEl.querySelectorAll(".checkbox-btn.checked");
  const countText = sessionEl.querySelector(".selected-count-text");
  const restoreBtn = sessionEl.querySelector(`.restore-button[data-id="${sessionId}"]`);

  if (countText) {
    countText.textContent = `${selectedRows.length}/${allRows.length} selected`;
  }
  if (restoreBtn) {
    restoreBtn.textContent = `Restore ${selectedRows.length} tabs`;
  }
}

function setAllCheckboxes(sessionEl, sessionId, checked) {
  sessionEl.querySelectorAll(".checkbox-btn").forEach((cb) => {
    cb.classList.toggle("checked", checked);
    cb.innerHTML = checked ? ICONS.check : "";
  });
  sessionEl.querySelectorAll(".tab-row").forEach((row) => {
    row.classList.toggle("selected", checked);
  });
  updateSelectionCounter(sessionEl, sessionId);
}

async function toggleInlineRename(sessionEl, sessionId, renameBtn) {
  const titleText = sessionEl.querySelector(".session-title-text");
  const isEditing = renameBtn.dataset.editing === "true";

  if (!isEditing) {
    // Enter rename mode
    const currentName = titleText.textContent;
    const input = document.createElement("input");
    input.type = "text";
    input.className = "rename-input";
    input.value = currentName;
    input.maxLength = 60;
    titleText.replaceWith(input);
    input.focus();
    input.select();

    renameBtn.dataset.editing = "true";
    renameBtn.innerHTML = ICONS.check;
    renameBtn.title = "Save name";

    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        saveInlineRename(sessionEl, sessionId, input.value, renameBtn);
      } else if (e.key === "Escape") {
        renderSessions();
      }
    });
  } else {
    // Save rename
    const input = sessionEl.querySelector(".rename-input");
    const val = input ? input.value : "";
    await saveInlineRename(sessionEl, sessionId, val, renameBtn);
  }
}

async function saveInlineRename(sessionEl, sessionId, newName, renameBtn) {
  const trimmed = newName.trim();
  if (trimmed) {
    const sessions = await getSessions();
    const s = sessions.find((item) => item.id === sessionId);
    if (s) {
      s.name = trimmed;
      await setSessions(sessions);
    }
  }
  if (renameBtn) {
    renameBtn.dataset.editing = "false";
    renameBtn.innerHTML = ICONS.pencil;
  }
  await renderSessions();
}

async function removeTabFromSession(sessionId, tabIndex) {
  const sessions = await getSessions();
  const session = sessions.find((s) => s.id === sessionId);
  if (!session) return;
  session.tabs.splice(tabIndex, 1);
  await setSessions(sessions);
  await renderSessions();
}

async function deleteSession(id) {
  const sessions = await getSessions();
  const filtered = sessions.filter((s) => s.id !== id);
  await setSessions(filtered);
  await renderSessions();
}

// ---------- restore ----------

async function restoreSession(id) {
  const sessions = await getSessions();
  const session = sessions.find((s) => s.id === id);
  if (!session || session.tabs.length === 0) return;

  const sessionEl = el.sessionsList.querySelector(`.session-card[data-id="${id}"]`);
  const allCheckboxes = sessionEl ? sessionEl.querySelectorAll(".checkbox-btn") : [];

  let tabsToRestore = session.tabs;
  // If checkbox UI exists, restore only what is actively checked
  if (allCheckboxes.length > 0) {
    const selectedIndices = new Set();
    sessionEl.querySelectorAll(".checkbox-btn.checked").forEach((cb) => {
      selectedIndices.add(Number(cb.dataset.index));
    });
    tabsToRestore = session.tabs.filter((_, i) => selectedIndices.has(i));
  }

  if (tabsToRestore.length === 0) {
    alert("No tabs selected to restore. Check at least one tab or hit 'Select all'.");
    return;
  }

  const total = tabsToRestore.length;

  if (total > LARGE_SESSION_WARNING_THRESHOLD) {
    const proceed = confirm(
      `This will open ${total} tabs. They'll load in a discarded (unloaded) state and only ` +
        `use real memory once you click into them. Continue?`
    );
    if (!proceed) return;
  }

  const restoreBtn = sessionEl ? sessionEl.querySelector(`.restore-button[data-id="${id}"]`) : null;
  if (restoreBtn) {
    restoreBtn.disabled = true;
    restoreBtn.textContent = "Restoring tabs...";
  }

  chrome.runtime.sendMessage({ type: "restoreSession", session: { ...session, tabs: tabsToRestore } }, (response) => {
    if (chrome.runtime.lastError) return;
    if (restoreBtn) {
      restoreBtn.disabled = false;
      restoreBtn.textContent = `Restore ${tabsToRestore.length} tabs`;
    }
    if (response && !response.ok) {
      setSaveStatus(`Restore failed: ${response.error}`, true);
    }
  });
}

// ---------- backup export / import ----------

[el.importTriggerSetup, el.importTriggerLock, el.importTriggerMain].forEach((btn) => {
  if (btn) btn.addEventListener("click", () => el.importInput.click());
});

el.exportBtn.addEventListener("click", async () => {
  const vault = await getVault();
  if (!vault) return;

  const blob = new Blob([JSON.stringify(vault, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  const date = new Date().toISOString().slice(0, 10);
  a.href = url;
  a.download = `incognito-tab-saver-backup-${date}.json`;
  a.click();
  URL.revokeObjectURL(url);
});

el.importInput.addEventListener("change", async (e) => {
  const file = e.target.files[0];
  e.target.value = "";
  if (!file) return;

  let candidate;
  try {
    const text = await file.text();
    candidate = JSON.parse(text);
  } catch {
    alert("That file isn't valid JSON — couldn't read it as a backup.");
    return;
  }

  if (!candidate || typeof candidate.salt !== "string" || typeof candidate.iv !== "string" || typeof candidate.data !== "string") {
    alert("That file doesn't look like a vault backup from this extension.");
    return;
  }

  const existingVault = await getVault();
  if (existingVault) {
    const proceed = confirm(
      "Importing will replace your current saved sessions with the ones in this backup file. This cannot be undone. Continue?"
    );
    if (!proceed) return;
  }

  await chrome.storage.local.set({ [VAULT_KEY]: candidate });
  cryptoKey = null;
  el.setupScreen.classList.add("hidden");
  el.mainContent.classList.add("hidden");
  el.headerLockBtn.classList.add("hidden");
  el.lockScreen.classList.remove("hidden");
  el.unlockStatus.textContent = "Backup imported — enter its password to unlock.";
  el.unlockPassword.focus();
});

// ---------- cloud backup / restore (Backblaze B2) ----------

async function handleCloudRestore() {
  const existingVault = await getVault();
  if (existingVault) {
    const proceed = confirm(
      "Restoring from Backblaze B2 will replace your current saved sessions with the cloud backup. This cannot be undone. Continue?"
    );
    if (!proceed) return;
  }

  if (el.setupStatus) el.setupStatus.textContent = "Pulling backup from Backblaze B2...";
  if (el.unlockStatus) el.unlockStatus.textContent = "Pulling backup from Backblaze B2...";

  chrome.runtime.sendMessage({ type: "cloudBackupPull" }, async (res) => {
    if (chrome.runtime.lastError || !res?.ok) {
      const err = res?.error || chrome.runtime.lastError?.message || "Failed to connect to B2 backup agent.";
      if (el.setupStatus) el.setupStatus.textContent = "Cloud restore failed: " + err;
      if (el.unlockStatus) el.unlockStatus.textContent = "Cloud restore failed: " + err;
      alert("Failed to restore from B2: " + err);
      return;
    }

    let candidate = res.data;
    if (typeof candidate === "string") {
      try {
        candidate = JSON.parse(candidate);
      } catch {
        alert("Downloaded backup from B2 isn't valid JSON.");
        return;
      }
    }

    if (!candidate || typeof candidate.salt !== "string" || typeof candidate.iv !== "string" || typeof candidate.data !== "string") {
      alert("Downloaded backup does not look like a valid encrypted vault.");
      return;
    }

    await chrome.storage.local.set({ [VAULT_KEY]: candidate });
    cryptoKey = null;
    el.setupScreen.classList.add("hidden");
    el.mainContent.classList.add("hidden");
    el.headerLockBtn.classList.add("hidden");
    el.lockScreen.classList.remove("hidden");
    el.unlockStatus.textContent = "Backup restored from B2 — enter your password to unlock.";
    el.unlockPassword.focus();
  });
}

[el.cloudRestoreSetup, el.cloudRestoreLock].forEach((btn) => {
  if (btn) btn.addEventListener("click", handleCloudRestore);
});

if (el.cloudPushBtn) {
  el.cloudPushBtn.addEventListener("click", async () => {
    const vault = await getVault();
    if (!vault) return;

    showToast("Backing up to Backblaze B2...", "info", 10000);
    chrome.runtime.sendMessage({ type: "cloudBackupPush" }, (res) => {
      if (chrome.runtime.lastError || !res?.ok) {
        const err = res?.error || chrome.runtime.lastError?.message || "Failed to push to B2";
        showToast("B2 backup failed: " + err, "error", 5000);
      } else {
        showToast("Backup pushed to Backblaze B2 successfully!", "success", 3500);
      }
    });
  });
}

// Run init
init();
