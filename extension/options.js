async function load() {
  const { backendUrl } = await chrome.storage.sync.get("backendUrl");
  document.getElementById("backendUrl").value = backendUrl || "https://phishing-detector-f65f.onrender.com";
}

document.getElementById("saveBtn").addEventListener("click", async () => {
  let url = document.getElementById("backendUrl").value.trim().replace(/\/+$/, "");
  await chrome.storage.sync.set({ backendUrl: url });
  const msg = document.getElementById("savedMsg");
  msg.style.display = "inline";
  setTimeout(() => (msg.style.display = "none"), 1500);
});

load();
