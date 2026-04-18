/* ═══════════════════════════════════════════════
   intel.js — Threat Intelligence IOC Manager
   ═══════════════════════════════════════════════ */

let chartIocCats = null;
let isIntelLoading = false;

async function loadIntelPage() {
  if (isIntelLoading) return;
  isIntelLoading = true;
  try {
    const typeFilter = document.getElementById("ioc-type-filter").value;
    const url = typeFilter ? `/iocs?type=${typeFilter}` : `/iocs`;
    const r = await apiGet(url);
    if (r.status !== "ok") return;
  const iocs = r.data;

  // IOC table
  const body = document.getElementById("ioc-body");
  if (!iocs.length) {
    body.innerHTML = `<tr><td colspan="7" class="empty">No IOCs loaded. Start the server and load sample logs.</td></tr>`;
  } else {
    body.innerHTML = iocs.map(i => `
      <tr>
        <td style="color:var(--text-muted);font-size:0.75rem">#${i.id}</td>
        <td>${i.type === "ip" ? '<span class="tag tag-ip">IP</span>' : '<span class="tag tag-domain">Domain</span>'}</td>
        <td>${mono(i.value)}</td>
        <td><span style="font-size:0.78rem;color:var(--amber)">${i.category || "—"}</span></td>
        <td>
          <div class="conf-bar">
            <div class="conf-track"><div class="conf-fill" style="width:${i.confidence || 0}%"></div></div>
            <span class="conf-val">${i.confidence}%</span>
          </div>
        </td>
        <td style="font-size:0.78rem;color:var(--text-secondary)">${i.source || "—"}</td>
        <td style="font-size:0.75rem;color:var(--text-muted)">${timeAgo(i.created_at)}</td>
      </tr>`).join("");
  }

  // Category chart
  const catCounts = {};
  iocs.forEach(i => { catCounts[i.category] = (catCounts[i.category] || 0) + 1; });
  buildIocCatChart(Object.keys(catCounts), Object.values(catCounts));
  } catch (e) {
    console.error("Intel page load error:", e);
  } finally {
    isIntelLoading = false;
  }
}

function buildIocCatChart(labels, data) {
  const ctx = document.getElementById("chart-ioc-cats");
  if (!ctx) return;
  const ctxC = ctx.getContext("2d");
  if (chartIocCats) chartIocCats.destroy();
  const colors = ["#ff3b57","#f5a623","#00d4ff","#00e676","#a855f7","#ff783c","#7dd3fc","#fbbf24"];
  chartIocCats = new Chart(ctxC, {
    type: "doughnut",
    data: {
      labels,
      datasets: [{
        data,
        backgroundColor: colors.slice(0, labels.length).map(c => c + "bb"),
        borderColor: colors.slice(0, labels.length),
        borderWidth: 2,
        hoverOffset: 6,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: true, position: "right", labels: { color: "#7a92b4", font: { size: 10 }, boxWidth: 12 } }
      },
      cutout: "60%",
    }
  });
}

// IOC Lookup
document.getElementById("btn-ioc-lookup").addEventListener("click", async () => {
  const val = document.getElementById("ioc-lookup-val").value.trim();
  const type = document.getElementById("ioc-lookup-type").value;
  const resEl = document.getElementById("ioc-lookup-result");
  if (!val) { resEl.textContent = "Enter a value to check."; return; }

  const body = type === "ip" ? { ip: val } : { domain: val };
  const r = await apiPost("/iocs/check", body);
  if (r.status !== "ok") { resEl.innerHTML = `<span class="ioc-hit-false">Error: ${r.message}</span>`; return; }
  const d = r.data;
  if (d.hit) {
    const meta = d.metadata || {};
    resEl.innerHTML = `
      <span class="ioc-hit-true">⚠ MALICIOUS — found in IOC database</span><br>
      <span style="font-size:0.78rem;color:var(--text-secondary)">
        Category: <strong>${meta.category || "—"}</strong> &nbsp;|&nbsp;
        Confidence: <strong>${meta.confidence || "—"}%</strong> &nbsp;|&nbsp;
        Source: <strong>${meta.source || "—"}</strong>
      </span>`;
  } else {
    resEl.innerHTML = `<span class="ioc-hit-false">✓ CLEAN — not found in IOC database</span>`;
  }
});

// Add IOC modal
document.getElementById("btn-add-ioc").addEventListener("click", () => {
  document.getElementById("add-ioc-overlay").classList.add("open");
});
function closeAddIocModal() {
  document.getElementById("add-ioc-overlay").classList.remove("open");
}
document.getElementById("add-ioc-close").addEventListener("click", closeAddIocModal);
document.getElementById("add-ioc-cancel").addEventListener("click", closeAddIocModal);
document.getElementById("add-ioc-overlay").addEventListener("click", e => {
  if (e.target === e.currentTarget) closeAddIocModal();
});

document.getElementById("add-ioc-submit").addEventListener("click", async () => {
  const ioc_type  = document.getElementById("new-ioc-type").value;
  const value     = document.getElementById("new-ioc-value").value.trim();
  const category  = document.getElementById("new-ioc-category").value.trim() || "unknown";
  const confidence = parseInt(document.getElementById("new-ioc-conf").value) || 80;
  if (!value) { toast("warning", "Value required."); return; }
  const r = await apiPost("/iocs", { type: ioc_type, value, category, confidence, source: "manual" });
  if (r.status === "ok") {
    toast("success", "IOC added.", value);
    closeAddIocModal();
    loadIntelPage();
    document.getElementById("new-ioc-value").value = "";
  } else {
    toast("error", "Failed", r.message);
  }
});

document.getElementById("ioc-type-filter").addEventListener("change", loadIntelPage);
document.getElementById("btn-refresh-intel").addEventListener("click", loadIntelPage);
registerPage("intel", loadIntelPage);
