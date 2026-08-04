const $ = (id) => document.getElementById(id);

// Restore saved API base.
chrome.storage?.local.get("apiBase", (data) => {
  if (data && data.apiBase) $("apiBase").value = data.apiBase;
});
$("apiBase").addEventListener("change", () => {
  chrome.storage?.local.set({ apiBase: $("apiBase").value.trim() });
});

$("scan").addEventListener("click", async () => {
  setBusy(true);
  setStatus("Reading page...");
  try {
    const text = await grabPageText();
    if (!text || text.trim().length < 10) {
      setStatus("Couldn't find message text. Select the text and try again, or paste it below.");
      return;
    }
    await analyze(text);
  } catch (err) {
    setStatus("Error: " + err.message);
  } finally {
    setBusy(false);
  }
});

$("scanManual").addEventListener("click", async () => {
  const text = $("manualText").value.trim();
  if (!text) return setStatus("Paste a message first.");
  setBusy(true);
  try {
    await analyze(text);
  } catch (err) {
    setStatus("Error: " + err.message);
  } finally {
    setBusy(false);
  }
});

// Inject an extractor into the active tab: prefer the user's selection, then
// known LinkedIn message containers, then a trimmed page body.
async function grabPageText() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.id) return "";
  const [{ result }] = await chrome.scripting.executeScript({
    target: { tabId: tab.id },
    func: () => {
      const sel = window.getSelection().toString().trim();
      if (sel.length > 20) return sel;
      const nodes = document.querySelectorAll(
        ".msg-s-event-listitem__body, .msg-s-message-group__meta, " +
          "[data-event-urn] .msg-s-event-listitem__body"
      );
      if (nodes.length) {
        return Array.from(nodes)
          .map((n) => n.innerText)
          .join("\n")
          .trim();
      }
      return (document.body.innerText || "").slice(0, 6000);
    },
  });
  return result || "";
}

async function analyze(text) {
  setStatus("Checking for scam patterns...");
  const base = $("apiBase").value.trim().replace(/\/$/, "");
  const resp = await fetch(base + "/analyze/message", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ text, platform: "extension", persist: false }),
  });
  if (!resp.ok) {
    let detail = resp.statusText;
    try {
      detail = (await resp.json()).detail || detail;
    } catch (_) {}
    throw new Error(detail);
  }
  const report = await resp.json();
  render(report);
  setStatus("");
}

const EMOJI = { LOW: "✅", MEDIUM: "⚠️", HIGH: "🚨" };
const ADVICE = {
  LOW: "Looks legitimate. Still use normal caution.",
  MEDIUM: "Some red flags. Verify before sharing anything.",
  HIGH: "Likely a scam. Don't share info/money or move to external chat apps.",
};

function render(report) {
  const level = report.verdict.risk_level;
  const flags = report.verdict.flags_detected;
  const e = report.entities;
  const chips = [
    ...e.telegram_handles.map((h) => "Telegram: @" + h),
    ...e.whatsapp_numbers.map((n) => "WhatsApp: " + n),
    ...e.phone_numbers.map((n) => "Phone: " + n),
    ...e.urls.map((u) => "Link: " + u),
  ];

  const parts = [
    `<div class="banner risk-${level}">
       <span class="emoji">${EMOJI[level]}</span>
       <div><div class="level">${level} RISK</div>
       <div class="summary">${esc(ADVICE[level])}</div></div>
     </div>`,
    `<div class="section-title">Red flags (${flags.length})</div>`,
    flags.length
      ? `<ul>${flags.map((f) => `<li>${esc(f)}</li>`).join("")}</ul>`
      : `<div class="notes">No scam patterns detected.</div>`,
  ];

  if (report.impersonation && report.impersonation.notes.length) {
    parts.push(`<div class="section-title">Impersonation</div>`);
    parts.push(
      `<div class="notes">${report.impersonation.notes.map(esc).join("<br/>")}</div>`
    );
  }
  if (chips.length) {
    parts.push(`<div class="section-title">Contacts & links</div>`);
    parts.push(
      `<div class="chips">${chips.map((c) => `<span class="chip">${esc(c)}</span>`).join("")}</div>`
    );
  }

  const r = $("result");
  r.innerHTML = parts.join("");
  r.classList.remove("hidden");
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}
function setStatus(m) { $("status").textContent = m; }
function setBusy(b) { $("scan").disabled = b; $("scanManual").disabled = b; }
