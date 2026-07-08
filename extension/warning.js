const params = new URLSearchParams(window.location.search);
const blockedUrl = params.get("url") || "";
const stage = params.get("stage") || "";
const confidence = params.get("confidence");
const note = params.get("note") || "";

document.getElementById("blockedUrl").textContent = blockedUrl;

const stageLabels = {
  blocklist: "matched a known-malicious domain list",
  typosquat: "closely resembles a known legitimate site",
  model: "flagged by the machine learning model",
};
let detailsText = stageLabels[stage] || "flagged as unsafe";
if (confidence) detailsText += ` (confidence: ${(parseFloat(confidence) * 100).toFixed(1)}%)`;
if (note) detailsText += ` — ${note}`;
document.getElementById("detailsBox").textContent = detailsText;

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
// handlers. Wire the buttons up here instead (see PROJECT_REVIEW.md 1.2).
document.getElementById("backBtn").addEventListener("click", goBack);
document.getElementById("proceedBtn").addEventListener("click", proceedAnyway);
