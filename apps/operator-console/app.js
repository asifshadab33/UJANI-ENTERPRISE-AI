const API_PATH = "/api/v1/operator/overview";
const byId = (id) => document.getElementById(id);
const connection = byId("connection");
const notice = byId("notice");
const refreshButton = byId("refresh");

function setConnection(label, state) {
  connection.textContent = label;
  connection.className = "status " + (state === "online" ? "status-online" : state === "error" ? "status-error" : "status-unknown");
}
function textCell(value) {
  const cell = document.createElement("td");
  cell.textContent = value == null || value === "" ? "—" : String(value);
  return cell;
}
function formatAge(timestamp) {
  if (!Number.isFinite(timestamp) || timestamp <= 0) return "Unknown";
  const age = Math.max(0, Date.now() - timestamp);
  if (age < 60_000) return "Just now";
  if (age < 3_600_000) return Math.floor(age / 60_000) + " min ago";
  if (age < 86_400_000) return Math.floor(age / 3_600_000) + " hr ago";
  return Math.floor(age / 86_400_000) + " days ago";
}
function pill(value) {
  const node = document.createElement("span");
  node.className = "pill";
  node.textContent = String(value ?? "unknown").replaceAll("_", " ");
  const normalized = String(value ?? "").toLowerCase();
  if (["trusted", "enrolled", "available", "approved", "schedulable", "online"].includes(normalized)) node.classList.add("pill-good");
  if (["stale", "busy", "pending", "sleeping", "paused"].includes(normalized)) node.classList.add("pill-warn");
  if (["revoked", "rejected", "ineligible", "offline"].includes(normalized)) node.classList.add("pill-bad");
  return node;
}
function renderDevices(records) {
  const body = byId("devices");
  body.replaceChildren();
  byId("device-count").textContent = records.length + " records";
  if (!records.length) {
    const row = document.createElement("tr");
    const cell = textCell("No live device inventory available.");
    cell.colSpan = 7; cell.className = "empty"; row.append(cell); body.append(row); return;
  }
  for (const device of records) {
    const row = document.createElement("tr");
    row.append(textCell(device.display_name || device.device_id));
    row.append(textCell(device.platform));
    const trust = document.createElement("td"); trust.append(pill(device.trust_state)); row.append(trust);
    const availability = document.createElement("td"); availability.append(pill(device.availability)); row.append(availability);
    row.append(textCell(device.remaining_cpu_millis == null ? null : (device.remaining_cpu_millis / 1000).toFixed(2) + " cores"));
    row.append(textCell(device.remaining_memory_mb == null ? null : Math.round(device.remaining_memory_mb).toLocaleString() + " MiB"));
    row.append(textCell(formatAge(device.last_seen_unix_ms)));
    body.append(row);
  }
}
function renderList(id, records, emptyText, detailKeys) {
  const root = byId(id); root.replaceChildren();
  if (!records.length) { root.textContent = emptyText; root.classList.add("empty"); return; }
  root.classList.remove("empty");
  for (const item of records) {
    const entry = document.createElement("div"); entry.className = "list-item";
    const title = document.createElement("strong"); title.textContent = item.title || item.workload_id || item.approval_id || "Untitled record";
    const detail = document.createElement("small");
    detail.textContent = detailKeys.map((key) => item[key]).filter((v) => v != null && v !== "").join(" · ") || "No additional details";
    entry.append(title, detail);
    if (item.state) entry.append(pill(item.state));
    root.append(entry);
  }
}
function validOverview(data) {
  return data && data.schema_version === 1
    && data.fleet && Number.isSafeInteger(data.fleet.registered_devices)
    && Number.isSafeInteger(data.fleet.trusted_consented_devices)
    && Number.isSafeInteger(data.fleet.online_fresh_devices)
    && Number.isSafeInteger(data.fleet.schedulable_devices)
    && Array.isArray(data.devices) && Array.isArray(data.workloads) && Array.isArray(data.approvals)
    && Number.isFinite(data.generated_at_unix_ms);
}
function renderOverview(data) {
  if (!validOverview(data)) throw new Error("The control plane returned an unsupported or incomplete overview schema.");
  byId("registered").textContent = data.fleet.registered_devices.toLocaleString();
  byId("trusted").textContent = data.fleet.trusted_consented_devices.toLocaleString();
  byId("online").textContent = data.fleet.online_fresh_devices.toLocaleString();
  byId("schedulable").textContent = data.fleet.schedulable_devices.toLocaleString();
  renderDevices(data.devices);
  renderList("workloads", data.workloads, "No active workloads.", ["state", "class", "reason"]);
  renderList("approvals", data.approvals, "No pending approvals.", ["requester", "scope", "expires_at"]);
  byId("updated").textContent = "Snapshot: " + new Date(data.generated_at_unix_ms).toLocaleString();
  notice.hidden = true;
  setConnection("Connected · live snapshot", "online");
}
async function refreshOverview() {
  refreshButton.disabled = true;
  setConnection("Connecting…", "unknown");
  try {
    const response = await fetch(API_PATH, {
      method: "GET",
      credentials: "same-origin",
      cache: "no-store",
      redirect: "error",
      headers: { "Accept": "application/json" }
    });
    if (response.status === 401 || response.status === 403) throw new Error("Sign in with an authorized Enterprise operator account to view this fleet.");
    if (response.status === 404) throw new Error("The Enterprise overview API is not deployed yet. No sample data is shown.");
    if (!response.ok) throw new Error("The control plane returned HTTP " + response.status + ".");
    const payload = await response.json();
    renderOverview(payload);
  } catch (error) {
    setConnection("Not connected", "error");
    notice.hidden = false;
    const heading = notice.querySelector("strong");
    const message = notice.querySelector("p");
    heading.textContent = "Live control-plane data unavailable";
    message.textContent = error instanceof Error ? error.message : "Could not load the Enterprise overview.";
  } finally {
    refreshButton.disabled = false;
  }
}
refreshButton.addEventListener("click", refreshOverview);
setConnection("Control plane not connected", "unknown");
