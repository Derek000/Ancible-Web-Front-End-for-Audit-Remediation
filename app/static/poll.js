function startPolling(elementId, url, intervalMs) {
  async function refresh() {
    try {
      const r = await fetch(url, {cache: "no-store"});
      if (!r.ok) return;
      const html = await r.text();
      const el = document.getElementById(elementId);
      if (el) el.innerHTML = html;
    } catch (e) {
      console.warn("poll error", e);
    }
    setTimeout(refresh, intervalMs);
  }
  setTimeout(refresh, intervalMs);
}

async function runPreflight(buttonId, tableBodyId, statusId) {
  const btn = document.getElementById(buttonId);
  btn.disabled = true;
  btn.innerText = "Checking...";
  try {
    const r = await fetch("/api/preflight", {cache: "no-store"});
    const data = await r.json();
    const tbody = document.getElementById(tableBodyId);
    tbody.innerHTML = "";
    for (const c of data.checks) {
      const tr = document.createElement("tr");
      const ok = c.ok ? "OK" : "Fail";
      const statusColor = c.ok ? "var(--ok)" : "var(--err)";
      const cmdsHtml = (c.fix && c.fix.cmds && c.fix.cmds.length) ?
        c.fix.cmds.map((cmd, i) => `<div class="cmd"><code>${cmd}</code> <button onclick="copyText(this.previousSibling.innerText)">Copy</button></div>`).join("") : "";
      const tipHtml = (c.fix && c.fix.tip) ? `<div class="tip">${c.fix.tip}</div>` : "";
      tr.innerHTML = `
        <td>${c.category}</td>
        <td>${c.name}</td>
        <td><span style="color:${statusColor}">${ok}</span></td>
        <td><code>${c.detail || ""}</code>${tipHtml}${cmdsHtml}</td>
      `;
      tbody.appendChild(tr);
    }
    const overall = data.overall_ok ? "<strong style='color:var(--ok)'>OK</strong>" : "<strong style='color:var(--err)'>Attention needed</strong>";
    document.getElementById(statusId).innerHTML = `Overall status: ${overall}`;
  } catch (e) {
    console.error(e);
    alert("Preflight failed to run. Check server logs.");
  } finally {
    btn.disabled = false;
    btn.innerText = "Run check again";
  }
}

function copyText(text) {
  navigator.clipboard.writeText(text);
}
