let currentTabUrl = "";

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

  const { urlCache } = await chrome.storage.session.get("urlCache");
  const cached = urlCache && urlCache[currentTabUrl];
  renderStatus(cached);

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
