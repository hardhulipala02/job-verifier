const API = ""; // same origin

const $ = (id) => document.getElementById(id);

// --- tab switching ---------------------------------------------------------
document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
    document.querySelectorAll(".panel").forEach((p) => p.classList.remove("active"));
    tab.classList.add("active");
    $(tab.dataset.tab).classList.add("active");
  });
});

// --- file upload label -----------------------------------------------------
$("emailFile").addEventListener("change", (e) => {
  const file = e.target.files[0];
  $("fileName").textContent = file ? file.name : "";
});

// --- actions ---------------------------------------------------------------
$("analyzeEmail").addEventListener("click", async () => {
  const file = $("emailFile").files[0];
  const text = $("emailText").value.trim();
  if (!file && !text) return setStatus("Paste an email or choose a .eml file.");

  setBusy("analyzeEmail", true);
  setStatus("Analyzing email...");
  try {
    let report;
    if (file) {
      const form = new FormData();
      form.append("file", file);
      report = await postForm(
        `/analyze/upload?persist=false&use_llm=${$("emailLlm").checked}`,
        form
      );
    } else {
      report = await postJson("/analyze", {
        raw_email: text,
        persist: false,
        use_llm: $("emailLlm").checked,
      });
    }
    renderReport(report, "email");
    setStatus("");
  } catch (err) {
    setStatus("Error: " + err.message);
  } finally {
    setBusy("analyzeEmail", false);
  }
});

$("analyzeMessage").addEventListener("click", async () => {
  const text = $("messageText").value.trim();
  if (!text) return setStatus("Paste a message first.");

  setBusy("analyzeMessage", true);
  setStatus("Analyzing message...");
  try {
    const report = await postJson("/analyze/message", {
      text,
      sender_name: $("senderName").value.trim() || null,
      platform: "web",
      persist: false,
      use_llm: $("messageLlm").checked,
    });
    renderReport(report, "message");
    setStatus("");
  } catch (err) {
    setStatus("Error: " + err.message);
  } finally {
    setBusy("analyzeMessage", false);
  }
});

// --- networking ------------------------------------------------------------
async function postJson(path, body) {
  const resp = await fetch(API + path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!resp.ok) throw new Error((await resp.json()).detail || resp.statusText);
  return resp.json();
}

async function postForm(path, form) {
  const resp = await fetch(API + path, { method: "POST", body: form });
  if (!resp.ok) throw new Error((await resp.json()).detail || resp.statusText);
  return resp.json();
}

// --- rendering -------------------------------------------------------------
const EMOJI = { LOW: "✅", MEDIUM: "⚠️", HIGH: "🚨" };
const ADVICE = {
  LOW: "Looks legitimate. Still use normal caution.",
  MEDIUM: "Be careful — some red flags. Verify before sharing anything.",
  HIGH: "Likely a scam. Do not share info or money, and do not move to external chat apps.",
};

function renderReport(report, mode) {
  const level = report.verdict.risk_level;
  const parts = [];

  parts.push(`
    <div class="verdict-banner risk-${level}">
      <span class="emoji">${EMOJI[level]}</span>
      <div>
        <div class="level">${level} RISK</div>
        <div class="summary">${escapeHtml(ADVICE[level])}</div>
      </div>
    </div>
  `);

  const src = report.source;
  if (src) {
    const rows = [`<div><strong>Report ID:</strong> ${escapeHtml(src.analysis_id)}</div>`];
    if (src.from_address) rows.push(`<div><strong>From:</strong> ${escapeHtml(src.from_address)}</div>`);
    if (src.subject) rows.push(`<div><strong>Subject:</strong> ${escapeHtml(src.subject)}</div>`);
    if (src.date) rows.push(`<div><strong>Date:</strong> ${escapeHtml(src.date)}</div>`);
    parts.push(`<div class="section-title">Analyzed email</div>`);
    parts.push(`<div class="notes">${rows.join("")}</div>`);
  }

  if (report.sender) {
    parts.push(
      `<div class="section-title">Sender</div><div>${escapeHtml(
        report.sender
      )}</div>`
    );
  }

  // Email authentication (only meaningful for the email path).
  if (mode === "email") {
    const s = report.security;
    parts.push(`<div class="section-title">Email authentication</div>
      <div class="auth-grid">
        ${authPill("SPF", s.spf)}
        ${authPill("DKIM", s.dkim)}
        ${authPill("DMARC", s.dmarc)}
      </div>`);
  }

  const flags = report.verdict.flags_detected;
  parts.push(`<div class="section-title">Red flags (${flags.length})</div>`);
  parts.push(
    flags.length
      ? `<ul class="flags">${flags
          .map((f) => `<li>${escapeHtml(f)}</li>`)
          .join("")}</ul>`
      : `<div class="notes">No scam patterns detected.</div>`
  );

  const imp = report.impersonation;
  if (imp && (imp.is_impersonation || (imp.notes && imp.notes.length))) {
    parts.push(`<div class="section-title">Impersonation</div>`);
    parts.push(
      `<div>${imp.is_impersonation ? "⚠️ Possible impersonation" : "None detected"}</div>`
    );
    if (imp.notes && imp.notes.length) {
      parts.push(
        `<div class="notes">${imp.notes.map(escapeHtml).join("<br/>")}</div>`
      );
    }
  }

  const role = report.role;
  if (role && (role.claimed_role || role.summary)) {
    parts.push(`<div class="section-title">Advertised role</div>`);
    if (role.claimed_role) {
      const mark = role.verified
        ? " ✅ verified"
        : role.checked
        ? " ⚠️ not found online"
        : "";
      parts.push(`<div>${escapeHtml(role.claimed_role)}${mark}</div>`);
    }
    if (role.summary) {
      parts.push(`<div class="notes">${escapeHtml(role.summary)}</div>`);
    }
    if (role.open_roles && role.open_roles.length) {
      const company = role.claimed_company || "this company";
      parts.push(`<div class="notes"><strong>Open roles at ${escapeHtml(company)}:</strong></div>`);
      parts.push(
        `<ul class="flags">${role.open_roles
          .map((o) => {
            const title = o.url
              ? `<a href="${escapeHtml(o.url)}" target="_blank">${escapeHtml(o.title)}</a>`
              : escapeHtml(o.title);
            return `<li>${title}${o.matches_claim ? " <strong>(matches)</strong>" : ""}</li>`;
          })
          .join("")}</ul>`
      );
    }
    if (role.sources && role.sources.length) {
      parts.push(
        `<div class="notes">${role.sources
          .map((u) => `<a href="${escapeHtml(u)}" target="_blank">${escapeHtml(u)}</a>`)
          .join("<br/>")}</div>`
      );
    }
  }

  const e = report.entities;
  const chips = [
    ...e.telegram_handles.map((h) => "Telegram: @" + h),
    ...e.whatsapp_numbers.map((n) => "WhatsApp: " + n),
    ...e.phone_numbers.map((n) => "Phone: " + n),
    ...e.urls.map((u) => "Link: " + u),
    ...e.domains.map((d) => "Domain: " + d),
  ];
  if (chips.length) {
    parts.push(`<div class="section-title">Extracted contacts & links</div>`);
    parts.push(
      `<div class="chips">${chips
        .map((c) => `<span class="chip">${escapeHtml(c)}</span>`)
        .join("")}</div>`
    );
  }

  const result = $("result");
  result.innerHTML = parts.join("");
  result.classList.remove("hidden");
  result.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function authPill(label, status) {
  const cls =
    status === "pass" ? "auth-pass" : status === "fail" ? "auth-fail" : "auth-other";
  return `<span class="auth-pill ${cls}">${label}: ${status}</span>`;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  }[c]));
}

function setStatus(msg) {
  $("status").textContent = msg;
}
function setBusy(id, busy) {
  $(id).disabled = busy;
}
