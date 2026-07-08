let currentTabUrl = "";

// Duplicated from background.js (same reasoning as escapeHtml being
// duplicated across every context in this extension - no bundler, so
// small stable constants/helpers get copied rather than imported. Keep
// these two in sync with background.js if either changes.
const IGNORED_SCHEMES = ["chrome:", "chrome-extension:", "about:", "edge:", "brave:", "file:"];
const CACHE_TTL_MS = 10 * 60 * 1000;
function isCacheFresh(entry) {
  return entry && Date.now() - entry.timestamp < CACHE_TTL_MS;
}

// result.note is backend-controlled today (low
// risk), but one compromised/misconfigured backend away from XSS inside
// the extension's own privileged popup context. Same escape pattern as
// app/main.py's embedded pages.
function escapeHtml(s) {
  const div = document.createElement("div");
  div.textContent = s == null ? "" : String(s);
  return div.innerHTML;
}

function renderStatus(result) {
  const area = document.getElementById("statusArea");
  if (!result) {
    area.innerHTML = `<span class="badge unknown">Not yet checked</span>`;
    return;
  }
  const cls = result.verdict === "safe" ? "safe" : "unsafe";
  const conf = result.confidence != null ? ` (${(result.confidence * 100).toFixed(1)}%)` : "";
  area.innerHTML = `
    <span class="badge ${cls}">${result.verdict.toUpperCase()}</span>
    <div class="row">Stage: ${result.stage}${conf}</div>
    ${result.note ? `<div class="row">${escapeHtml(result.note)}</div>` : ""}
  `;
}

async function init() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  currentTabUrl = tab.url || "";
  document.getElementById("currentUrl").textContent = currentTabUrl;

  // Found via real user testing: checking the popup right after typing a
  // new URL and hitting Enter can catch the tab BEFORE navigation
  // commits - tab.url is still the previous page (often chrome://newtab/)
  // even though the address bar already shows the new URL. Show that
  // plainly instead of silently querying a cache keyed by the wrong URL.
  if (IGNORED_SCHEMES.some((s) => currentTabUrl.startsWith(s))) {
    document.getElementById("statusArea").innerHTML =
      `<span class="badge unknown">This type of page cannot be checked</span>`;
    document.getElementById("checkBtn").disabled = true;
    const { autoCheckEnabled } = await chrome.storage.sync.get("autoCheckEnabled");
    document.getElementById("autoCheckToggle").checked = autoCheckEnabled !== false;
    return;
  }

  const { urlCache } = await chrome.storage.session.get("urlCache");
  const cached = urlCache && urlCache[currentTabUrl];
  // Found via real user testing: this used to render ANY cached entry
  // with no freshness check, unlike every other read path in the
  // extension - a stale/expired result could be shown as if current.
  renderStatus(isCacheFresh(cached) ? cached : null);

  const { autoCheckEnabled } = await chrome.storage.sync.get("autoCheckEnabled");
  document.getElementById("autoCheckToggle").checked = autoCheckEnabled !== false;
}

document.getElementById("checkBtn").addEventListener("click", () => {
  const btn = document.getElementById("checkBtn");
  btn.disabled = true;
  btn.textContent = "Checking...";
  chrome.runtime.sendMessage({ type: "MANUAL_CHECK", url: currentTabUrl }, (response) => {
    btn.disabled = false;
    btn.textContent = "Check this page";
    if (response && response.ok) {
      renderStatus(response.result);
    } else {
      document.getElementById("statusArea").innerHTML =
        `<span class="badge unknown">Error - is the backend reachable?</span>`;
    }
  });
});

document.getElementById("autoCheckToggle").addEventListener("change", (e) => {
  chrome.storage.sync.set({ autoCheckEnabled: e.target.checked });
});

init();
