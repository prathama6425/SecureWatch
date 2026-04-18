/* ═══════════════════════════════════════════════
   logs.js — Log Viewer with filtering
   ═══════════════════════════════════════════════ */

async function loadLogs() {
  const typeFilter = document.getElementById("log-type-filter").value;
  const ipFilter   = document.getElementById("log-ip-filter").value.trim();
  let url = `/logs?limit=200`;
  if (typeFilter) url += `&type=${typeFilter}`;

  let r;
  if (ipFilter) {
    r = await apiGet(`/logs/ip/${encodeURIComponent(ipFilter)}`);
  } else {
    r = await apiGet(url);
  }

  const body = document.getElementById("logs-body");
  if (r.status !== "ok" || !r.data.length) {
    body.innerHTML = `<tr><td colspan="8" class="empty">No logs found. Load sample logs from the Dashboard.</td></tr>`;
    return;
  }

  body.innerHTML = r.data.map((log, idx) => `
    <tr>
      <td style="color:var(--text-muted);font-size:0.72rem">${log.id || idx + 1}</td>
      <td style="font-size:0.72rem;color:var(--text-muted);white-space:nowrap">${(log.timestamp||"").substring(11,19)}</td>
      <td>${sourceTag(log.source_type || "—")}</td>
      <td>${mono(log.source_ip || "—")}</td>
      <td>${mono(log.username || "—")}</td>
      <td style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:0.78rem;color:var(--text-secondary)" title="${log.action || ""}">${log.action || "—"}</td>
      <td>
        ${log.status === "FAILURE" || log.status === "BLOCK" || log.status === "DROP"
          ? `<span style="color:var(--red);font-size:0.72rem;font-weight:600">${log.status}</span>`
          : `<span style="color:var(--green);font-size:0.72rem;font-weight:600">${log.status || "—"}</span>`}
      </td>
      <td style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:0.75rem;color:var(--text-secondary)" title="${(log.message||"").replace(/"/g,"'")}">${log.message || "—"}</td>
    </tr>`).join("");
}

document.getElementById("log-type-filter").addEventListener("change", loadLogs);
document.getElementById("log-ip-filter").addEventListener("keydown", e => {
  if (e.key === "Enter") loadLogs();
});
document.getElementById("btn-refresh-logs").addEventListener("click", loadLogs);

registerPage("logs", loadLogs);
