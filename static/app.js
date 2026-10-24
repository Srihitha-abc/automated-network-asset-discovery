const $ = (id) => document.getElementById(id);
let key = localStorage.getItem("assetApiKey") || "";
const headers = () => ({ "X-API-Key": key, "Content-Type": "application/json" });
async function api(path, options = {}) {
  const response = await fetch(path, { ...options, headers: { ...headers(), ...(options.headers || {}) } });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "Request failed");
  return data;
}
function renderTable(target, headers, rows) {
  $(target).innerHTML = rows.length ? `<table><thead><tr>${headers.map(h => `<th>${h}</th>`).join("")}</tr></thead><tbody>${rows.join("")}</tbody></table>` : "<p>No records found.</p>";
}
function escapeHtml(value) {
  return String(value ?? "-").replace(/[&<>"']/g, character => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;"
  }[character]));
}
async function refresh() {
  if (!key) return;
  try {
    const [assets, changes, status] = await Promise.all([
      api(`/api/assets?q=${encodeURIComponent($("search").value)}&service=${encodeURIComponent($("service").value)}`),
      api("/api/changes"), api("/api/status")
    ]);
    $("asset-count").textContent = assets.assets.length;
    $("change-count").textContent = changes.changes.length;
    $("scan-state").textContent = status.running ? "Running" : (status.last_error ? "Error" : "Idle");
    renderTable("assets", ["IP", "Hostname", "MAC", "Last seen", "Services"], assets.assets.map(a => `<tr><td>${escapeHtml(a.ip_address)}</td><td>${escapeHtml(a.hostname)}</td><td>${escapeHtml(a.mac_address)}</td><td>${escapeHtml(a.last_seen)}</td><td>${escapeHtml(a.services)}</td></tr>`));
    renderTable("changes", ["Time", "IP", "Type", "Description"], changes.changes.map(c => `<tr><td>${escapeHtml(c.created_at)}</td><td>${escapeHtml(c.ip_address)}</td><td>${escapeHtml(c.change_type)}</td><td>${escapeHtml(c.description)}</td></tr>`));
  } catch (error) { $("auth-message").textContent = error.message; $("auth-message").className = "error"; }
}
$("save-key").onclick = () => { key = $("api-key").value.trim(); localStorage.setItem("assetApiKey", key); $("auth-message").textContent = "Connected"; $("auth-message").className = "success"; refresh(); };
$("scan").onclick = async () => { $("scan").disabled = true; try { const data = await api("/api/scans", { method: "POST", body: JSON.stringify({ target: $("target").value }) }); $("scan-message").textContent = data.message; setTimeout(refresh, 1000); } catch (e) { $("scan-message").textContent = e.message; $("scan-message").className = "error"; } finally { $("scan").disabled = false; } };
["search", "service"].forEach(id => $(id).addEventListener("input", refresh));
if (key) { $("api-key").value = key; refresh(); } setInterval(refresh, 5000);
