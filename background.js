const RESTORE_BATCH_SIZE = 5; // Concurrency cap: 5 tabs per batch (safely within socket limits)
const RESTORE_BATCH_DELAY_MS = 200; // Pause between batches so the browser can settle
const TIER1_BACKGROUND_TIMEOUT_MS = 2500; // Window for passive background commit
const TIER2_ACTIVE_TIMEOUT_MS = 1500; // Window for sequential forced foreground activation

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// True commit check: pendingUrl must be cleared, and url must be non-empty and not about:blank
function isTabCommitted(tab) {
  return !!(tab && !tab.pendingUrl && tab.url && tab.url !== "about:blank");
}

// Wait for a tab to truly commit (!pendingUrl && url !== "about:blank")
function waitForTabCommit(tabId, timeoutMs) {
  return new Promise((resolve) => {
    let settled = false;

    const finish = (committed) => {
      if (settled) return;
      settled = true;
      chrome.tabs.onUpdated.removeListener(listener);
      clearTimeout(timer);
      resolve(committed);
    };

    const listener = (updatedTabId, changeInfo, tab) => {
      if (updatedTabId !== tabId) return;
      if (isTabCommitted(tab)) {
        finish(true);
      }
    };

    chrome.tabs.onUpdated.addListener(listener);

    // Initial check in case it already committed
    chrome.tabs.get(tabId).then((existingTab) => {
      if (settled) return;
      if (isTabCommitted(existingTab)) {
        finish(true);
      }
    }).catch(() => {});

    const timer = setTimeout(() => {
      // Final poll before timeout to avoid race condition
      chrome.tabs.get(tabId).then((existingTab) => {
        finish(isTabCommitted(existingTab));
      }).catch(() => {
        finish(false);
      });
    }, timeoutMs);
  });
}

async function restoreSessionTabs(session) {
  const total = session.tabs.length;
  if (total === 0) return;

  const bounds = session.windowBounds || {};
  const isIncognitoAllowed = await new Promise((r) => chrome.extension.isAllowedIncognitoAccess(r));
  const incognito = (session.incognito !== false) && isIncognitoAllowed;
  const createOpts = { url: session.tabs[0].url, incognito };

  // width/height/left/top can't be combined with state:"maximized"/"fullscreen" —
  // Chrome rejects the call — so only apply explicit bounds for a normal window.
  if (bounds.state === "maximized" || bounds.state === "fullscreen") {
    createOpts.state = bounds.state;
  } else {
    if (Number.isFinite(bounds.width)) createOpts.width = bounds.width;
    if (Number.isFinite(bounds.height)) createOpts.height = bounds.height;
    if (Number.isFinite(bounds.left)) createOpts.left = bounds.left;
    if (Number.isFinite(bounds.top)) createOpts.top = bounds.top;
  }

  const win = await chrome.windows.create(createOpts);
  const firstTabId = win.tabs && win.tabs[0] && win.tabs[0].id;
  if (firstTabId && session.tabs[0].pinned) {
    await chrome.tabs.update(firstTabId, { pinned: true });
  }

  // Restore subsequent tabs in bounded batches with two-tier commit handling
  for (let i = 1; i < total; i += RESTORE_BATCH_SIZE) {
    const batch = session.tabs.slice(i, i + RESTORE_BATCH_SIZE);

    // 1. Create all tabs in this batch as inactive
    const createdTabs = await Promise.all(
      batch.map(async (t) => {
        const tab = await chrome.tabs.create({
          windowId: win.id,
          url: t.url,
          pinned: !!t.pinned,
          active: false,
        });
        return tab;
      })
    );

    // 2. Tier 1: Wait in parallel for background commit.
    // Fast tabs commit and get discarded immediately as they finish.
    const stragglers = [];

    await Promise.all(
      createdTabs.map(async (tab) => {
        const committed = await waitForTabCommit(tab.id, TIER1_BACKGROUND_TIMEOUT_MS);
        if (committed) {
          const currentTab = await chrome.tabs.get(tab.id).catch(() => null);
          if (isTabCommitted(currentTab)) {
            try {
              await chrome.tabs.discard(tab.id);
            } catch (err) {
              // Discard failed or tab closed; non-fatal
            }
            return;
          }
        }
        // If not committed in background within Tier 1, queue as straggler for Tier 2
        stragglers.push(tab);
      })
    );

    // 3. Tier 2: Process stragglers SEQUENTIALLY with forced foreground activation
    for (const straggler of stragglers) {
      try {
        // A. Force activate straggler to elevate its network request to HIGHEST priority
        await chrome.tabs.update(straggler.id, { active: true });

        // B. Wait up to TIER2_ACTIVE_TIMEOUT_MS for it to commit in foreground
        await waitForTabCommit(straggler.id, TIER2_ACTIVE_TIMEOUT_MS);

        // C. Always switch focus back to anchor first tab
        try {
          await chrome.tabs.update(firstTabId, { active: true });
        } catch {}

        // D. Verify committed state before discarding
        const currentTab = await chrome.tabs.get(straggler.id).catch(() => null);
        if (isTabCommitted(currentTab)) {
          try {
            await chrome.tabs.discard(straggler.id);
          } catch (err) {
            // Discard failed; non-fatal
          }
        }
        // Tier 3: Dead/unreachable URL bailout.
        // If still uncommitted, we do NOT discard it, leaving the tab alive
        // displaying its error page rather than about:blank.
      } catch (err) {
        // Tab closed or window error; continue safely
      }
    }

    if (i + RESTORE_BATCH_SIZE < total) {
      await sleep(RESTORE_BATCH_DELAY_MS);
    }
  }
}

const NATIVE_HOST_NAME = "com.incognito_tab_saver.backup_agent";

function pingNativeHost() {
  return new Promise((resolve) => {
    chrome.runtime.sendNativeMessage(NATIVE_HOST_NAME, { op: "ping" }, (response) => {
      if (chrome.runtime.lastError) {
        resolve({ ok: false, error: chrome.runtime.lastError.message });
      } else {
        resolve({ ok: true, response });
      }
    });
  });
}

function pushVaultToCloud(vaultData) {
  return new Promise((resolve) => {
    chrome.runtime.sendNativeMessage(NATIVE_HOST_NAME, { op: "push", payload: vaultData }, (response) => {
      if (chrome.runtime.lastError) {
        resolve({ ok: false, error: chrome.runtime.lastError.message });
      } else if (response?.status === "ok") {
        resolve({ ok: true, timestamp: response.timestamp, bytes: response.bytes });
      } else {
        resolve({ ok: false, error: response?.error || "Push failed" });
      }
    });
  });
}

function pullVaultFromCloud() {
  return new Promise((resolve) => {
    chrome.runtime.sendNativeMessage(NATIVE_HOST_NAME, { op: "pull" }, (response) => {
      if (chrome.runtime.lastError) {
        resolve({ ok: false, error: chrome.runtime.lastError.message });
      } else if (response?.status === "ok") {
        resolve({ ok: true, data: response.data, timestamp: response.timestamp });
      } else {
        resolve({ ok: false, error: response?.error || "Pull failed" });
      }
    });
  });
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "restoreSession") {
    restoreSessionTabs(message.session)
      .then(() => sendResponse({ ok: true }))
      .catch((err) => sendResponse({ ok: false, error: String(err) }));
    return true; // keep the message channel open for the async response
  }

  if (message?.type === "pingNativeHost") {
    pingNativeHost()
      .then(sendResponse)
      .catch((err) => sendResponse({ ok: false, error: String(err) }));
    return true;
  }

  if (message?.type === "cloudBackupPush") {
    chrome.storage.local.get("vault").then((data) => {
      if (!data?.vault) {
        sendResponse({ ok: false, error: "No vault found to back up" });
        return;
      }
      pushVaultToCloud(data.vault).then(sendResponse);
    }).catch((err) => sendResponse({ ok: false, error: String(err) }));
    return true;
  }

  if (message?.type === "cloudBackupPull") {
    pullVaultFromCloud().then(sendResponse);
    return true;
  }
});

// Self-test ping on startup
pingNativeHost().then((res) => {
  console.log("[NMH-INIT-PING]", res);
});

