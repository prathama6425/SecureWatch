/* ═══════════════════════════════════════════════
   reports.js — SOC Report Generation & Viewer
   ═══════════════════════════════════════════════ */

async function loadReports() {
  const r = await apiGet("/reports");
  const body = document.getElementById("reports-body");
  if (r.status !== "ok" || !r.data.length) {
    body.innerHTML = `<tr><td colspan="5" class="empty">No reports generated yet. Click Daily or Weekly above.</td></tr>`;
    return;
  }
  body.innerHTML = r.data.map(rp => `
    <tr>
      <td style="color:var(--text-muted);font-size:0.75rem">#${rp.id}</td>
      <td><span class="badge ${rp.report_type === "weekly" ? "badge-HIGH" : "badge-MEDIUM"}">${rp.report_type.toUpperCase()}</span></td>
      <td style="font-size:0.82rem">${rp.period}</td>
      <td style="font-size:0.75rem;color:var(--text-muted)">${timeAgo(rp.created_at)}</td>
      <td>
        <button class="action-btn" onclick="previewReport(${rp.id})">Preview</button>
        <a href="${'http://localhost:5000/api'}/reports/${rp.id}/html" target="_blank" class="action-btn" style="text-decoration:none;display:inline-block;padding:2px 8px">Open ↗</a>
      </td>
    </tr>`).join("");
}

function previewReport(id) {
  const preview = document.getElementById("report-preview");
  document.getElementById("report-iframe").src = `http://localhost:5000/api/reports/${id}/html`;
  preview.style.display = "block";
  preview.scrollIntoView({ behavior: "smooth" });
}

document.getElementById("close-report-preview").addEventListener("click", () => {
  document.getElementById("report-preview").style.display = "none";
  document.getElementById("report-iframe").src = "";
});

document.getElementById("btn-gen-daily").addEventListener("click", async () => {
  const btn = document.getElementById("btn-gen-daily");
  btn.disabled = true; btn.textContent = "⏳ Generating…";
  const r = await apiPost("/reports/generate/daily");
  btn.disabled = false; btn.textContent = "📋 Daily Report";
  if (r.status === "ok") {
    toast("success", "Daily report generated.", `Period: ${r.data.period}`);
    const d = r.data.summary;
    if (d) {
      toast("info", `${d.total_alerts || 0} alerts, ${d.total_incidents || 0} incidents`, "Report summary", 6000);
    }
    loadReports();
  } else {
    toast("error", "Generation failed", r.message);
  }
});

document.getElementById("btn-gen-weekly").addEventListener("click", async () => {
  const btn = document.getElementById("btn-gen-weekly");
  btn.disabled = true; btn.textContent = "⏳ Generating…";
  const r = await apiPost("/reports/generate/weekly");
  btn.disabled = false; btn.textContent = "📊 Weekly Report";
  if (r.status === "ok") {
    toast("success", "Weekly report generated.", `Period: ${r.data.period}`);
    loadReports();
  } else {
    toast("error", "Generation failed", r.message);
  }
});

registerPage("reports", loadReports);
