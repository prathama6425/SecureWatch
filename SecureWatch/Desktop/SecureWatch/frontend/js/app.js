/* ═══════════════════════════════════════════════════════
   app.js — Core SOC Lab Application
   Handles: auth, routing, API calls, WebSocket, toasts
   ═══════════════════════════════════════════════════════ */

const API = "http://localhost:5000/api";
let authToken = localStorage.getItem("soc_token") || "";
let currentUser = JSON.parse(localStorage.getItem("soc_user") || "null");
let wsSocket = null;

/* ── Auth helpers ──────────────────────────────────────── */
function getHeaders() {
  return { "Content-Type": "application/json", "X-Auth-Token": authToken };
}

async function apiGet(path) {
  const r = await fetch(`${API}${path}`, { headers: getHeaders() });
  return r.json();
}

async function apiPost(path, body = {}) {
  const r = await fetch(`${API}${path}`, {
    method: "POST", headers: getHeaders(), body: JSON.stringify(body)
  });
  return r.json();
}

async function apiPatch(path, body = {}) {
  const r = await fetch(`${API}${path}`, {
    method: "PATCH", headers: getHeaders(), body: JSON.stringify(body)
  });
  return r.json();
}

/* ── Toast notifications ───────────────────────────────── */
function toast(type, title, msg = "", duration = 4000) {
  const icons = { success: "✓", error: "✗", warning: "⚠", info: "ℹ" };
  const el = document.createElement("div");
  el.className = `toast toast-${type}`;
  el.innerHTML = `
    <span class="toast-icon">${icons[type] || "ℹ"}</span>
    <div class="toast-text">
      <div class="toast-title">${title}</div>
      ${msg ? `<div class="toast-msg">${msg}</div>` : ""}
    </div>`;
  document.getElementById("toast-container").appendChild(el);
  setTimeout(() => el.remove(), duration);
}

/* ── Router ────────────────────────────────────────────── */
const pageLoaders = {}; // Registered by each module

function navigate(pageId) {
  document.querySelectorAll(".page").forEach(p => p.classList.remove("active"));
  document.querySelectorAll(".nav-item").forEach(n => n.classList.remove("active"));
  const page = document.getElementById(`page-${pageId}`);
  const navEl = document.getElementById(`nav-${pageId}`);
  if (page) page.classList.add("active");
  if (navEl) navEl.classList.add("active");
  document.getElementById("breadcrumb").textContent =
    navEl ? navEl.textContent.trim().replace(/\d+$/, "").trim() : pageId;
  if (pageLoaders[pageId]) pageLoaders[pageId]();
}

function registerPage(id, loader) {
  pageLoaders[id] = loader;
}

/* ── Sidebar navigation ────────────────────────────────── */
document.querySelectorAll(".nav-item[data-page], a[data-page]").forEach(el => {
  el.addEventListener("click", e => {
    e.preventDefault();
    navigate(el.dataset.page);
  });
});

document.getElementById("sidebar-toggle").addEventListener("click", () => {
  document.getElementById("sidebar").classList.toggle("collapsed");
  document.getElementById("main-content").classList.toggle("expanded");
});

/* ── Live clock ────────────────────────────────────────── */
function updateClock() {
  const now = new Date();
  document.getElementById("clock").textContent =
    now.toLocaleTimeString("en-IN", { hour12: false }) +
    " IST";
}
setInterval(updateClock, 1000);
updateClock();

/* ── WebSocket setup ───────────────────────────────────── */
function initWebSocket() {
  if (typeof io === "undefined") return;
  wsSocket = io("http://localhost:5000", { transports: ["websocket", "polling"] });

  wsSocket.on("connect", () => {
    document.getElementById("ws-dot").className = "status-dot online";
    document.getElementById("ws-text").textContent = "Live";
    toast("success", "WebSocket Connected", "Real-time alert streaming active.");
  });

  wsSocket.on("disconnect", () => {
    document.getElementById("ws-dot").className = "status-dot offline";
    document.getElementById("ws-text").textContent = "Offline";
  });

  wsSocket.on("new_alerts", data => {
    if (data.count > 0) {
      toast("error", `${data.count} New Alert${data.count > 1 ? "s" : ""}`,
        data.alerts.map(a => a.rule_name).join(", "), 6000);
      updateAlertBadge();
      if (pageLoaders["dashboard"]) pageLoaders["dashboard"]();
    }
  });

  wsSocket.on("new_incident", inc => {
    toast("warning", "New Incident", `#${inc.id}: ${inc.title}`);
  });

  wsSocket.on("simulation_complete", data => {
    toast("info", "Simulation Complete",
      `${data.type} — ${data.logs} logs, ${data.alerts} alerts`);
  });
}

/* ── Alert badge ───────────────────────────────────────── */
async function updateAlertBadge() {
  try {
    const r = await apiGet("/alerts?status=OPEN&limit=1");
    const n = r.data ? r.data.length : 0;
    const badge = document.getElementById("alerts-badge");
    badge.textContent = n;
    badge.style.display = n > 0 ? "inline" : "none";
  } catch {}
}

/* ── Login flow ────────────────────────────────────────── */
async function doLogin() {
  const user = document.getElementById("login-username").value.trim();
  const pass = document.getElementById("login-password").value.trim();
  const errEl = document.getElementById("login-error");
  errEl.textContent = "";
  try {
    const r = await fetch(`${API}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: user, password: pass })
    });
    const data = await r.json();
    if (data.status !== "ok") { errEl.textContent = data.message; return; }
    authToken = data.data.token;
    currentUser = { username: data.data.username, role: data.data.role };
    localStorage.setItem("soc_token", authToken);
    localStorage.setItem("soc_user", JSON.stringify(currentUser));
    applySession();
  } catch (e) {
    errEl.textContent = "Cannot connect to backend. Is it running?";
  }
}

function applySession() {
  document.getElementById("login-overlay").style.display = "none";
  document.getElementById("user-name-display").textContent = currentUser.username;
  document.getElementById("user-role-display").textContent = currentUser.role;
  document.getElementById("user-avatar").textContent = currentUser.username[0].toUpperCase();
  initWebSocket();
  navigate("dashboard");
  updateAlertBadge();
  setInterval(updateAlertBadge, 30000);
}

document.getElementById("btn-login").addEventListener("click", doLogin);
document.getElementById("login-password").addEventListener("keydown", e => {
  if (e.key === "Enter") doLogin();
});
document.getElementById("btn-logout").addEventListener("click", () => {
  authToken = ""; currentUser = null;
  localStorage.clear();
  if (wsSocket) wsSocket.disconnect();
  document.getElementById("login-overlay").style.display = "flex";
});

/* ── Utility: badge HTML ───────────────────────────────── */
function severityBadge(sev) {
  return `<span class="badge badge-${sev}">${sev}</span>`;
}
function statusBadge(st) {
  return `<span class="badge badge-${st}">${st}</span>`;
}
function sourceTag(src) {
  return `<span class="tag tag-${src}">${src}</span>`;
}
function mono(text) {
  return `<span class="mono">${text || "—"}</span>`;
}
function timeAgo(ts) {
  if (!ts) return "—";
  const d = new Date(ts);
  const diff = Math.floor((Date.now() - d) / 1000);
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return d.toLocaleDateString();
}

/* ── Load sample logs button ───────────────────────────── */
document.getElementById("btn-load-samples").addEventListener("click", async () => {
  toast("info", "Loading sample logs…", "Ingesting Linux, web and firewall logs.");
  const r = await apiPost("/logs/load-samples");
  if (r.status === "ok") {
    toast("success", "Logs Loaded", `${r.data.logs_ingested} log entries, ${r.data.alerts_generated} alerts.`);
    if (pageLoaders["dashboard"]) pageLoaders["dashboard"]();
  } else {
    toast("error", "Load Failed", r.message);
  }
});

/* ── Auto-login from stored token ──────────────────────── */
if (authToken && currentUser) {
  applySession();
}
