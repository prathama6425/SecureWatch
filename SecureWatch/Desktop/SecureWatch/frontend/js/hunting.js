/* ═══════════════════════════════════════════════
   hunting.js — Threat Hunting Interface
   ═══════════════════════════════════════════════ */

let activeHuntQuery = null;

async function loadHuntingPage() {
  const r = await apiGet("/hunt/queries");
  if (r.status !== "ok") return;
  const list = r.data;
  const container = document.getElementById("hunt-query-list");
  container.innerHTML = list.map(q => `
    <div class="hunt-query-item" data-id="${q.id}" onclick="runHunt('${q.id}', this)">
      <div class="hunt-query-name">${q.name}</div>
      <div class="hunt-query-cat">${q.category}</div>
    </div>`).join("");
}

async function runHunt(queryId, el) {
  // Active state
  document.querySelectorAll(".hunt-query-item").forEach(i => i.classList.remove("active"));
  if (el) el.classList.add("active");
  activeHuntQuery = queryId;

  document.getElementById("hunt-results").innerHTML =
    `<div style="padding:2rem;text-align:center;color:var(--text-muted)">⏳ Running hunt…</div>`;

  const r = await apiGet(`/hunt/run/${queryId}`);
  if (r.status !== "ok") {
    toast("error", "Hunt failed", r.message);
    return;
  }
  renderHuntResults(r.data);
}

async function runCustomHunt() {
  const sql = document.getElementById("hunt-custom-sql").value.trim();
  if (!sql) { toast("warning", "Enter a SQL query first."); return; }

  document.getElementById("hunt-results").innerHTML =
    `<div style="padding:2rem;text-align:center;color:var(--text-muted)">⏳ Executing…</div>`;

  const r = await apiPost("/hunt/custom", { sql });
  if (r.status !== "ok") {
    toast("error", "Query error", r.message);
    document.getElementById("hunt-results").innerHTML =
      `<div style="padding:1.5rem;color:var(--red);font-family:'JetBrains Mono',monospace;font-size:0.8rem">${r.message}</div>`;
    return;
  }
  renderHuntResults(r.data);
}

function renderHuntResults(data) {
  const header = document.getElementById("hunt-result-header");
  header.style.display = "flex";
  document.getElementById("hunt-result-title").textContent = data.name || "Results";
  document.getElementById("hunt-result-count").textContent = `${data.result_count} row${data.result_count !== 1 ? "s" : ""}`;

  const container = document.getElementById("hunt-results");

  if (!data.results || data.results.length === 0) {
    container.innerHTML = `<div style="padding:2rem;text-align:center;color:var(--text-muted)">✓ No results — this hunt returned nothing suspicious.</div>`;
    return;
  }

  // Build dynamic table from result keys
  const keys = Object.keys(data.results[0]);
  const isHighlight = (k, v) => {
    if (k === "severity") return severityBadge(v);
    if (k === "status")   return statusBadge(v);
    if (k === "source_type") return sourceTag(v) ;
    if (k === "type")    return sourceTag(v);
    const monoCols = ["source_ip","ip","value","attempts","cnt","result_count","confidence"];
    if (monoCols.includes(k) && v !== null) return mono(v);
    return v === null || v === "" ? '<span style="color:var(--text-muted)">—</span>' : v;
  };

  container.innerHTML = `
    <table class="data-table">
      <thead><tr>${keys.map(k => `<th>${k.replace(/_/g," ")}</th>`).join("")}</tr></thead>
      <tbody>
        ${data.results.map(row => `
          <tr>${keys.map(k => `<td style="font-size:0.8rem">${isHighlight(k, row[k])}</td>`).join("")}</tr>
        `).join("")}
      </tbody>
    </table>`;

  toast("success", `Hunt complete`, `${data.result_count} results for "${data.name}"`);
}

document.getElementById("btn-hunt-run-custom").addEventListener("click", runCustomHunt);
registerPage("hunting", loadHuntingPage);
