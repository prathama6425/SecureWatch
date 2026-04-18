/* ═══════════════════════════════════════════════
   incidents.js — IR Case Management
   ═══════════════════════════════════════════════ */

async function loadIncidents() {
  const r = await apiGet("/incidents");
  if (r.status !== "ok") return;
  const list = r.data;
  const stats = r.stats || {};

  // Update lane counts
  ["TRIAGE","INVESTIGATE","RESPOND","CLOSED"].forEach(s => {
    const el = document.getElementById(`lane-${s}`);
    if (el) el.textContent = (stats.by_status && stats.by_status[s]) || 0;
  });

  const body = document.getElementById("incidents-body");
  if (!list.length) {
    body.innerHTML = `<tr><td colspan="8" class="empty">No incidents. Create one from an alert.</td></tr>`;
    return;
  }
  body.innerHTML = list.map(i => `
    <tr>
      <td style="color:var(--text-muted);font-size:0.75rem">#${i.id}</td>
      <td style="max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:0.83rem" title="${i.title}">${i.title}</td>
      <td>${severityBadge(i.severity)}</td>
      <td>${statusBadge(i.status)}</td>
      <td style="font-size:0.8rem">${i.assigned_to || '<span style="color:var(--text-muted)">Unassigned</span>'}</td>
      <td style="font-size:0.78rem;color:var(--cyan)">${(i.alert_ids||[]).length}</td>
      <td style="font-size:0.75rem;color:var(--text-muted)">${timeAgo(i.created_at)}</td>
      <td>
        <button class="action-btn" onclick="openIncidentModal(${i.id})">Detail</button>
        ${i.status !== "CLOSED" ? `<button class="action-btn" onclick="advanceIncident(${i.id}, '${nextStatus(i.status)}')">→ ${nextStatus(i.status)}</button>` : ""}
      </td>
    </tr>`).join("");
}

function nextStatus(current) {
  const flow = ["TRIAGE","INVESTIGATE","RESPOND","CLOSED"];
  const idx = flow.indexOf(current);
  return idx >= 0 && idx < flow.length - 1 ? flow[idx + 1] : "CLOSED";
}

async function advanceIncident(id, newStatus) {
  const r = await apiPost(`/incidents/${id}/transition`, { status: newStatus, note: `Advanced to ${newStatus} by analyst.` });
  if (r.status === "ok") {
    toast("success", `Incident #${id} → ${newStatus}`);
    loadIncidents();
  } else {
    toast("error", "Action failed", r.message);
  }
}

async function openIncidentModal(id) {
  const r = await apiGet(`/incidents/${id}`);
  if (r.status !== "ok") { toast("error", "Not found"); return; }
  const i = r.data;
  const tl = i.timeline || [];

  document.getElementById("incident-modal-title").textContent = `Incident #${i.id} — ${i.title}`;
  document.getElementById("incident-modal-body").innerHTML = `
    <div class="alert-detail" style="margin-bottom:1rem">
      <div class="detail-row"><span class="detail-label">Severity</span><span class="detail-value">${severityBadge(i.severity)}</span></div>
      <div class="detail-row"><span class="detail-label">Status</span><span class="detail-value">${statusBadge(i.status)}</span></div>
      <div class="detail-row"><span class="detail-label">Assigned To</span><span class="detail-value">${i.assigned_to || "Unassigned"}</span></div>
      <div class="detail-row"><span class="detail-label">Alert IDs</span><span class="detail-value">${(i.alert_ids||[]).join(", ")||"—"}</span></div>
      <div class="detail-row"><span class="detail-label">Created</span><span class="detail-value" style="font-size:0.78rem">${i.created_at}</span></div>
      ${i.notes ? `<div style="margin-top:0.5rem;font-size:0.78rem;color:var(--text-secondary);background:var(--bg-elevated);padding:0.6rem;border-radius:6px;white-space:pre-wrap">${i.notes}</div>` : ""}
    </div>
    <div style="font-size:0.78rem;font-weight:700;text-transform:uppercase;letter-spacing:0.08em;color:var(--text-muted);margin-bottom:0.5rem">Timeline</div>
    <div class="timeline">
      ${tl.length ? tl.map(e => `
        <div class="timeline-event">
          <span class="timeline-ts">${e.timestamp||""}</span>
          <span class="timeline-by">${e.by||"system"}</span>
          <span class="timeline-detail">${e.detail||""}</span>
        </div>`).join("") : '<div style="color:var(--text-muted);font-size:0.8rem;padding:0.5rem">No timeline events.</div>'}
    </div>
    <hr class="divider"/>
    <div style="display:flex;gap:0.6rem;align-items:center;flex-wrap:wrap">
      <input id="inc-note-input" class="text-input" placeholder="Add analyst note…" style="flex:1;min-width:160px"/>
      <button class="btn btn-ghost btn-sm" onclick="addIncidentNote(${i.id})">+ Add Note</button>
      ${i.status !== "CLOSED" ? `<button class="btn btn-primary btn-sm" onclick="advanceIncident(${i.id},'${nextStatus(i.status)}');closeIncidentModal()">→ Advance to ${nextStatus(i.status)}</button>` : ""}
    </div>`;

  document.getElementById("incident-modal-overlay").classList.add("open");
}

async function addIncidentNote(incId) {
  const noteEl = document.getElementById("inc-note-input");
  const note = noteEl.value.trim();
  if (!note) return;
  const r = await apiPost(`/incidents/${incId}/note`, { note });
  if (r.status === "ok") {
    toast("success", "Note added.");
    noteEl.value = "";
    openIncidentModal(incId); // Refresh modal
    loadIncidents();
  }
}

function closeIncidentModal() {
  document.getElementById("incident-modal-overlay").classList.remove("open");
}

document.getElementById("incident-modal-close").addEventListener("click", closeIncidentModal);
document.getElementById("incident-modal-overlay").addEventListener("click", e => {
  if (e.target === e.currentTarget) closeIncidentModal();
});

// Create incident
document.getElementById("btn-create-incident").addEventListener("click", () => {
  document.getElementById("create-inc-overlay").classList.add("open");
});

function closeCreateModal() {
  document.getElementById("create-inc-overlay").classList.remove("open");
}

document.getElementById("create-inc-close").addEventListener("click", closeCreateModal);
document.getElementById("create-inc-cancel").addEventListener("click", closeCreateModal);
document.getElementById("create-inc-overlay").addEventListener("click", e => {
  if (e.target === e.currentTarget) closeCreateModal();
});

document.getElementById("create-inc-submit").addEventListener("click", async () => {
  const title    = document.getElementById("inc-title").value.trim();
  const severity = document.getElementById("inc-severity").value;
  const assigned = document.getElementById("inc-assigned").value.trim() || currentUser?.username;
  if (!title) { toast("warning", "Title required."); return; }
  const r = await apiPost("/incidents", { title, severity, assigned_to: assigned, alert_ids: [] });
  if (r.status === "ok") {
    toast("success", "Incident created.", `#${r.data.id}: ${title}`);
    closeCreateModal();
    loadIncidents();
    document.getElementById("inc-title").value = "";
  } else {
    toast("error", "Failed", r.message);
  }
});

document.getElementById("btn-refresh-incidents").addEventListener("click", loadIncidents);
registerPage("incidents", loadIncidents);
