// background.js
// ==============
// Core logic. Intercepts top-level navigations via webNavigation (NOT the
// address bar itself - no extension can read keystrokes typed there; this
// fires the moment the browser starts navigating to a URL, which is the
// practical equivalent and early enough to warn before the page loads).
//
// HONEST LIMITATION: Manifest V3 does not allow extensions to synchronously
// block navigation while an async check runs (that capability - blocking
// webRequest - was removed in MV3 for most extensions). So this checks and
// redirects AS FAST AS POSSIBLE after navigation starts, rather than
// guaranteeing zero content ever renders. In practice, with a warm backend,
// this is usually fast enough that nothing perceptible loads - but on a
// slow/cold-started free-tier backend, a brief flash of the real page is
// possible before the redirect lands. This is a platform constraint, not a
// bug - the same constraint every MV3 safe-browsing-style extension faces.

const DEFAULT_SETTINGS = {
  backendUrl: "https://phishing-detector-f65f.onrender.com",
  autoCheckEnabled: true,
};

const CACHE_TTL_MS = 10 * 60 * 1000;      // 10 min: re-check a site periodically
const TEMP_ALLOW_TTL_MS = 5 * 60 * 1000;  // 5 min: "proceed anyway" grace period
const IGNORED_SCHEMES = ["chrome:", "chrome-extension:", "about:", "edge:", "brave:", "file:"];

chrome.runtime.onInstalled.addListener(async () => {
  const existing = await chrome.storage.sync.get(Object.keys(DEFAULT_SETTINGS));
  const toSet = {};
  for (const [k, v] of Object.entries(DEFAULT_SETTINGS)) {
    if (existing[k] === undefined) toSet[k] = v;
  }
  if (Object.keys(toSet).length) await chrome.storage.sync.set(toSet);
});

async function getSettings() {
  const stored = await chrome.storage.sync.get(Object.keys(DEFAULT_SETTINGS));
  return { ...DEFAULT_SETTINGS, ...stored };
}

async function getCache() {
  const { urlCache } = await chrome.storage.session.get("urlCache");
  return urlCache || {};
}
async function setCacheEntry(url, entry) {
  const cache = await getCache();
  cache[url] = { ...entry, timestamp: Date.now() };
  await chrome.storage.session.set({ urlCache: cache });
}
function isCacheFresh(entry) {
  return entry && Date.now() - entry.timestamp < CACHE_TTL_MS;
}

async function getTempAllow() {
  const { tempAllow } = await chrome.storage.session.get("tempAllow");
  return tempAllow || {};
}
async function addTempAllow(url) {
  const allow = await getTempAllow();
  allow[url] = Date.now();
  await chrome.storage.session.set({ tempAllow: allow });
}
function isTempAllowed(allowMap, url) {
  const ts = allowMap[url];
  return ts && Date.now() - ts < TEMP_ALLOW_TTL_MS;
}

async function checkUrlWithBackend(url, backendUrl) {
  const res = await fetch(`${backendUrl}/api/check`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });
  if (!res.ok) throw new Error(`Backend returned ${res.status}`);
  return res.json();
}

function setBadge(tabId, verdict) {
  if (verdict === "unsafe") {
    chrome.action.setBadgeText({ tabId, text: "!" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#dc2626" });
  } else if (verdict === "safe") {
    chrome.action.setBadgeText({ tabId, text: "" }); // clear - safe is the quiet default
  } else {
    chrome.action.setBadgeText({ tabId, text: "?" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#6b7280" });
  }
}

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return; // only top-level page loads, not iframes/ads
  const url = details.url;
  if (IGNORED_SCHEMES.some((s) => url.startsWith(s))) return;

  const settings = await getSettings();
  if (!settings.autoCheckEnabled) return;

  const tempAllow = await getTempAllow();
  if (isTempAllowed(tempAllow, url)) return; // user already said "proceed anyway"

  const cache = await getCache();
  const cached = cache[url];
  if (isCacheFresh(cached)) {
    setBadge(details.tabId, cached.verdict);
    if (cached.verdict === "unsafe") redirectToWarning(details.tabId, url, cached);
    return;
  }

  try {
    const result = await checkUrlWithBackend(url, settings.backendUrl);
    await setCacheEntry(url, result);
    setBadge(details.tabId, result.verdict);
    if (result.verdict === "unsafe") redirectToWarning(details.tabId, url, result);
  } catch (err) {
    // Backend unreachable (cold start, offline, misconfigured URL) - fail
    // OPEN, not closed: don't block browsing just because the checker is
    // down. Badge shows "?" so it's visible rather than silently swallowed.
    console.warn("Phishing checker: backend unreachable", err);
    setBadge(details.tabId, null);
  }
});

function redirectToWarning(tabId, blockedUrl, result) {
  const params = new URLSearchParams({
    url: blockedUrl,
    stage: result.stage || "",
    confidence: result.confidence != null ? result.confidence : "",
    note: result.note || "",
  });
  const warningUrl = chrome.runtime.getURL(`warning.html?${params.toString()}`);
  chrome.tabs.update(tabId, { url: warningUrl });
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "PROCEED_ANYWAY") {
    addTempAllow(message.url).then(() => {
      if (sender.tab) chrome.tabs.update(sender.tab.id, { url: message.url });
      sendResponse({ ok: true });
    });
    return true; // async response
  }
  if (message.type === "MANUAL_CHECK") {
    getSettings().then(async (settings) => {
      try {
        const result = await checkUrlWithBackend(message.url, settings.backendUrl);
        await setCacheEntry(message.url, result);
        sendResponse({ ok: true, result });
      } catch (err) {
        sendResponse({ ok: false, error: String(err) });
      }
    });
    return true; // async response
  }
});
