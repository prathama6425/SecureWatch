/* ═══════════════════════════════════════════════
   alerts.js — Alert table + detail modal
   ═══════════════════════════════════════════════ */

let selectedAlertId = null;

async function loadAlerts() {
  const status = document.getElementById("alert-filter-status").value;
  const url = status ? `/alerts?status=${status}&limit=300` : `/alerts?limit=300`;
  const r = await apiGet(url);
  const body = document.getElementById("alerts-body");
  if (r.status !== "ok" || !r.data.length) {
    body.innerHTML = `<tr><td colspan="9" class="empty">No alerts found.</td></tr>`;
    return;
  }
  body.innerHTML = r.data.map(a => `
    <tr>
      <td style="font-size:0.75rem;color:var(--text-muted)">#${a.id}</td>
      <td>${severityBadge(a.severity)}</td>
      <td style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:0.82rem">${a.rule_name}</td>
      <td>${mono(a.source_ip || "—")}</td>
      <td>${mono(a.username || "—")}</td>
      <td style="font-size:0.78rem;color:var(--text-secondary)">${a.mitre_tactic || "—"} ${a.mitre_tech ? `<span style="color:var(--cyan-dim)">[${a.mitre_tech}]</span>` : ""}</td>
      <td>${statusBadge(a.status)}</td>
      <td style="font-size:0.75rem;color:var(--text-muted);white-space:nowrap">${timeAgo(a.timestamp)}</td>
      <td>
        <button class="action-btn" onclick="openAlertModal(${a.id})">Detail</button>
        ${a.status === "OPEN" ? `<button class="action-btn" onclick="quickAck(${a.id})">ACK</button>` : ""}
      </td>
    </tr>`).join("");
}

async function openAlertModal(alertId) {
  selectedAlertId = alertId;
  const r = await apiGet(`/alerts/${alertId}`);
  if (r.status !== "ok") { toast("error", "Not found"); return; }
  const a = r.data;
  document.getElementById("modal-alert-title").textContent = `Alert #${a.id} — ${a.rule_name}`;
  document.getElementById("alert-modal-body").innerHTML = `
    <div class="alert-detail">
      <div class="detail-row"><span class="detail-label">Severity</span><span class="detail-value">${severityBadge(a.severity)}</span></div>
      <div class="detail-row"><span class="detail-label">Status</span><span class="detail-value">${statusBadge(a.status)}</span></div>
      <div class="detail-row"><span class="detail-label">Rule ID</span><span class="detail-value">${mono(a.rule_id)}</span></div>
      <div class="detail-row"><span class="detail-label">Source IP</span><span class="detail-value">${mono(a.source_ip || "—")}</span></div>
      <div class="detail-row"><span class="detail-label">Username</span><span class="detail-value">${mono(a.username || "—")}</span></div>
      <div class="detail-row"><span class="detail-label">MITRE Tactic</span><span class="detail-value" style="color:var(--purple)">${a.mitre_tactic || "—"}</span></div>
      <div class="detail-row"><span class="detail-label">MITRE Tech</span><span class="detail-value" style="color:var(--cyan)">${a.mitre_tech || "—"}</span></div>
      <div class="detail-row"><span class="detail-label">Timestamp</span><span class="detail-value" style="font-size:0.78rem">${a.timestamp}</span></div>
      <hr class="divider" />
      <div style="font-size:0.8rem;color:var(--text-secondary);line-height:1.6;padding:0.5rem;background:var(--bg-elevated);border-radius:6px">${a.description}</div>
    </div>`;
  document.getElementById("alert-modal-overlay").classList.add("open");
}

async function quickAck(alertId) {
  const r = await apiPatch(`/alerts/${alertId}/status`, { status: "ACK" });
  if (r.status === "ok") { toast("success", "Alert acknowledged."); loadAlerts(); }
}

// Modal footer buttons
document.getElementById("modal-ack-btn").addEventListener("click", async () => {
  if (!selectedAlertId) return;
  const r = await apiPatch(`/alerts/${selectedAlertId}/status`, { status: "ACK" });
  if (r.status === "ok") {
    toast("success", "Acknowledged", `Alert #${selectedAlertId} acknowledged.`);
    closeAlertModal(); loadAlerts();
  }
});

document.getElementById("modal-close-btn").addEventListener("click", async () => {
  if (!selectedAlertId) return;
  const r = await apiPatch(`/alerts/${selectedAlertId}/status`, { status: "CLOSED" });
  if (r.status === "ok") {
    toast("success", "Alert closed."); closeAlertModal(); loadAlerts();
  }
});

document.getElementById("modal-create-inc-btn").addEventListener("click", () => {
  closeAlertModal();
  navigate("incidents");
  // Pre-fill the create incident modal
  document.getElementById("create-inc-overlay").classList.add("open");
});

function closeAlertModal() {
  document.getElementById("alert-modal-overlay").classList.remove("open");
  selectedAlertId = null;
}

document.getElementById("alert-modal-close").addEventListener("click", closeAlertModal);
document.getElementById("alert-modal-overlay").addEventListener("click", e => {
  if (e.target === e.currentTarget) closeAlertModal();
});

document.getElementById("alert-filter-status").addEventListener("change", loadAlerts);
document.getElementById("btn-refresh-alerts").addEventListener("click", loadAlerts);

registerPage("alerts", loadAlerts);
