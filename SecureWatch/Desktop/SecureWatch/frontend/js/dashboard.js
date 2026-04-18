/* ═══════════════════════════════════════════════
   dashboard.js — KPI metrics + Chart.js charts
   ═══════════════════════════════════════════════ */

let chartTrend = null, chartSeverity = null, chartTactics = null;
let isLoadingDashboard = false;

const CHART_DEFAULTS = {
  responsive: true,
  maintainAspectRatio: false,
  plugins: { legend: { display: false } },
};

const CYAN = "#00d4ff", RED = "#ff3b57", AMBER = "#f5a623",
      GREEN = "#00e676", PURPLE = "#a855f7", ORANGE = "#ff783c";

function buildTrendChart(labels, data) {
  const ctx = document.getElementById("chart-trend").getContext("2d");
  if (chartTrend) chartTrend.destroy();
  chartTrend = new Chart(ctx, {
    type: "line",
    data: {
      labels,
      datasets: [{
        label: "Alerts",
        data,
        borderColor: CYAN,
        backgroundColor: "rgba(0,212,255,0.08)",
        fill: true,
        tension: 0.4,
        pointBackgroundColor: CYAN,
        pointRadius: 4,
        pointHoverRadius: 6,
      }]
    },
    options: {
      ...CHART_DEFAULTS,
      scales: {
        x: { ticks: { color: "#7a92b4", font: { size: 10 } }, grid: { color: "#1e2d45" } },
        y: { ticks: { color: "#7a92b4", font: { size: 10 } }, grid: { color: "#1e2d45" }, beginAtZero: true }
      }
    }
  });
}

function buildSeverityChart(sev) {
  const ctx = document.getElementById("chart-severity").getContext("2d");
  if (chartSeverity) chartSeverity.destroy();
  const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
  const colors = [RED, ORANGE, AMBER, GREEN];
  const labels = [], data = [], bgs = [];
  order.forEach((s, i) => {
    const row = sev.find(r => r.severity === s);
    if (row && row.cnt > 0) {
      labels.push(s); data.push(row.cnt); bgs.push(colors[i]);
    }
  });
  chartSeverity = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels,
      datasets: [{
        data,
        backgroundColor: bgs.map(c => c + "cc"),
        borderColor: bgs,
        borderWidth: 2,
        hoverOffset: 6,
      }]
    },
    options: {
      ...CHART_DEFAULTS,
      plugins: {
        legend: {
          display: true,
          position: "right",
          labels: { color: "#7a92b4", font: { size: 10 }, boxWidth: 12 }
        }
      },
      cutout: "65%",
    }
  });
}

function buildTacticsChart(tactics) {
  const ctx = document.getElementById("chart-tactics").getContext("2d");
  if (chartTactics) chartTactics.destroy();
  const labels = tactics.map(t => t.mitre_tactic.split(" ")[0]);
  const values = tactics.map(t => t.cnt);
  chartTactics = new Chart(ctx, {
    type: "bar",
    data: {
      labels,
      datasets: [{
        data: values,
        backgroundColor: PURPLE + "99",
        borderColor: PURPLE,
        borderWidth: 1,
        borderRadius: 4,
      }]
    },
    options: {
      ...CHART_DEFAULTS,
      indexAxis: "y",
      scales: {
        x: { ticks: { color: "#7a92b4", font: { size: 10 } }, grid: { color: "#1e2d45" }, beginAtZero: true },
        y: { ticks: { color: "#7a92b4", font: { size: 9 } }, grid: { display: false } }
      }
    }
  });
}

async function loadDashboard() {
  if (isLoadingDashboard) return;
  isLoadingDashboard = true;
  try {
    const r = await apiGet("/dashboard");
    if (r.status !== "ok") return;
    const d = r.data;
    const t = d.totals;

    // KPIs
    document.getElementById("kpi-open-alerts").textContent   = t.open_alerts;
    document.getElementById("kpi-total-alerts").textContent  = `${t.alerts} total`;
    document.getElementById("kpi-critical").textContent      = d.severity.critical;
    document.getElementById("kpi-incidents").textContent     = t.open_incidents;
    document.getElementById("kpi-total-inc").textContent     = `${t.incidents} total`;
    document.getElementById("kpi-logs").textContent          = t.logs;
    document.getElementById("kpi-iocs").textContent          = `${t.iocs} IOCs loaded`;

    // Alert badge
    const badge = document.getElementById("alerts-badge");
    badge.textContent = t.open_alerts;
    badge.style.display = t.open_alerts > 0 ? "inline" : "none";

    // Charts
    if (d.alert_trend.length) {
      buildTrendChart(
        d.alert_trend.map(r => r.day),
        d.alert_trend.map(r => r.cnt)
      );
    }
    if (d.severity_breakdown.length) buildSeverityChart(d.severity_breakdown);
    if (d.mitre_tactics.length) buildTacticsChart(d.mitre_tactics);

    // Top IPs table
    const ipBody = document.getElementById("top-ips-body");
    if (d.top_ips.length === 0) {
      ipBody.innerHTML = `<tr><td colspan="3" class="empty">No data — load sample logs first.</td></tr>`;
    } else {
      ipBody.innerHTML = d.top_ips.map(row => `
        <tr>
          <td>${mono(row.source_ip)}</td>
          <td><span class="badge badge-HIGH">${row.cnt}</span></td>
          <td>
            <button class="action-btn" onclick="navigate('logs');document.getElementById('log-ip-filter').value='${row.source_ip}';loadLogs()">View Logs</button>
          </td>
        </tr>`).join("");
    }

    // Recent alerts table
    const raBody = document.getElementById("recent-alerts-body");
    if (d.recent_alerts.length === 0) {
      raBody.innerHTML = `<tr><td colspan="4" class="empty">No alerts yet.</td></tr>`;
    } else {
      raBody.innerHTML = d.recent_alerts.map(a => `
        <tr>
          <td>${severityBadge(a.severity)}</td>
          <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${a.rule_name}</td>
          <td>${mono(a.source_ip || "—")}</td>
          <td style="font-size:0.75rem;color:var(--text-muted)">${timeAgo(a.timestamp)}</td>
        </tr>`).join("");
    }
  } catch (e) {
    console.error("Dashboard load error:", e);
  } finally {
    isLoadingDashboard = false;
  }
}

document.getElementById("btn-refresh-dash").addEventListener("click", loadDashboard);
registerPage("dashboard", loadDashboard);
