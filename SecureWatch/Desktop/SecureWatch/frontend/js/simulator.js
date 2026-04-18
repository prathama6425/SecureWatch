/* ═══════════════════════════════════════════════
   simulator.js — Attack Simulation Controls
   ═══════════════════════════════════════════════ */

function termLog(msg, cls = "") {
  const terminal = document.getElementById("sim-terminal");
  const card = document.getElementById("sim-terminal-card");
  card.style.display = "block";
  const line = document.createElement("div");
  line.className = `terminal-line ${cls}`;
  line.textContent = msg;
  terminal.appendChild(line);
  terminal.scrollTop = terminal.scrollHeight;
}

function termClear() {
  document.getElementById("sim-terminal").innerHTML = "";
}

function formatSimResult(result) {
  const ts = new Date().toLocaleTimeString("en-IN", { hour12: false });
  termLog(`[${ts}] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`, "t-dim");
  termLog(`[${ts}] SIMULATION: ${result.simulation?.toUpperCase() || "UNKNOWN"}`, "t-info");
  termLog(`[${ts}] Attacker IP: ${result.attacker_ip || "N/A"}`, "");
  if (result.target_ip)    termLog(`[${ts}] Target IP:   ${result.target_ip}`, "");
  if (result.target_user)  termLog(`[${ts}] Target User: ${result.target_user}`, "");
  if (result.attempts)     termLog(`[${ts}] Attempts:    ${result.attempts}`, "");
  if (result.ports_scanned)termLog(`[${ts}] Ports Scanned: ${result.ports_scanned}`, "");
  if (result.scenario)     termLog(`[${ts}] Scenario:    ${result.scenario}`, "");
  const logsIngested = result.logs_ingested || result.total_logs || 0;
  const alertsGen    = result.alerts_generated || result.total_alerts || 0;
  termLog(`[${ts}] Logs Ingested:     ${logsIngested}`, "");
  termLog(`[${ts}] Alerts Generated:  ${alertsGen}`, alertsGen > 0 ? "t-warn" : "");

  if (result.alerts && result.alerts.length > 0) {
    termLog(`[${ts}] ── Alert Summary ──────────────────────────`, "t-dim");
    result.alerts.forEach(a => {
      termLog(`[${ts}]   [${a.severity}] ${a.rule_name} — ${a.description?.substring(0, 80) || ""}`, 
        a.severity === "CRITICAL" ? "t-err" : "t-warn");
    });
  }

  if (result.stage_results) {
    termLog(`[${ts}] ── Full Chain Results ──────────────────────`, "t-dim");
    Object.entries(result.stage_results).forEach(([stage, stageRes]) => {
      termLog(`[${ts}]   Stage [${stage}]: ${stageRes.logs_ingested||0} logs, ${stageRes.alerts_generated||0} alerts`, "t-info");
    });
  }

  termLog(`[${ts}] ✓ Simulation complete. Check Alerts + Dashboard.`, "t-info");
  termLog("", "t-dim");
}

async function runSimulation(type, ipField) {
  const attackerIp = ipField ? ipField.value.trim() : "";
  const body = { type };
  if (attackerIp) body.attacker_ip = attackerIp;

  termLog(``, "t-dim");
  termLog(`[${new Date().toLocaleTimeString()}] Starting simulation: ${type}…`, "t-info");

  const r = await apiPost("/simulate", body);
  if (r.status === "ok") {
    formatSimResult(r.data);
    if (pageLoaders["dashboard"]) pageLoaders["dashboard"]();
  } else {
    termLog(`[ERROR] ${r.message || "Simulation failed. Ensure you're logged in as admin."}`, "t-err");
    toast("error", "Simulation failed", r.message);
  }
}

// Attach all sim buttons
document.querySelectorAll(".sim-run-btn").forEach(btn => {
  btn.addEventListener("click", async () => {
    const type = btn.dataset.type;
    const ipInputMap = {
      brute_force:  document.getElementById("sim-bf-ip"),
      port_scan:    document.getElementById("sim-ps-ip"),
      phishing_web: document.getElementById("sim-ph-ip"),
      full_chain:   document.getElementById("sim-fc-ip"),
    };
    btn.disabled = true;
    btn.textContent = "⏳ Running…";
    await runSimulation(type, ipInputMap[type]);
    btn.disabled = false;
    btn.textContent = type === "full_chain" ? "▶ Run Full Chain" : "▶ Run Simulation";
  });
});

document.getElementById("clear-terminal").addEventListener("click", termClear);
registerPage("simulator", () => {});
