const params = new URLSearchParams(window.location.search);
const blockedUrl = params.get("url") || "";

document.getElementById("blockedUrl").textContent = blockedUrl;

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
