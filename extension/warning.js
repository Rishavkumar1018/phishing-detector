const params = new URLSearchParams(window.location.search);
const blockedUrl = params.get("url") || "";

document.getElementById("blockedUrl").textContent = blockedUrl;

// 2026-07 audit fix: background.js has always built `reason` (and
// note/stage/confidence before it) into these query params, but nothing
// here ever read them - the block page showed only a generic hardcoded
// sentence, never the actual reason a site was flagged. `.textContent`,
// not innerHTML, so this is safe against a reason string containing
// markup without needing a separate escape helper (same end result as
// popup.js's escapeHtml(), just via the DOM API directly since this is
// the only dynamic text on this page).
const reason = params.get("reason") || "";
if (reason) {
  const reasonBox = document.getElementById("reasonBox");
  reasonBox.textContent = reason;
  reasonBox.classList.add("visible");
}

function goBack() {
  if (window.history.length > 1) {
    window.history.back();
  } else {
    window.close();
  }
}

function proceedAnyway() {
  chrome.runtime.sendMessage({ type: "PROCEED_ANYWAY", url: blockedUrl }, () => {
    // background.js navigates the tab directly once it registers the
    // temporary allow - nothing further to do here.
  });
}

// MV3 pages run under CSP script-src 'self', which blocks inline onclick
// handlers. Wire the buttons up here instead .
document.getElementById("backBtn").addEventListener("click", goBack);
document.getElementById("proceedBtn").addEventListener("click", proceedAnyway);
