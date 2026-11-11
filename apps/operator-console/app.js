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

function boundedString(value, max) {
  return typeof value === "string" && value.length > 0 && value.length <= max;
}
function validEvidence(evidence) {
  return evidence && ["runtime_api", "os_api", "runtime_metadata", "signed_catalogue", "published_catalogue", "estimate", "unknown"].includes(evidence.source)
    && ["verified", "reported", "estimated", "unknown"].includes(evidence.confidence)
    && (evidence.observed_at_unix_ms === null || (Number.isSafeInteger(evidence.observed_at_unix_ms) && evidence.observed_at_unix_ms > 0));
}
function validModelInventory(entries) {
  if (entries === undefined) return true;
  if (!Array.isArray(entries) || entries.length > 10000) return false;
  return entries.every((entry) => {
    const inventory = entry && entry.inventory;
    return entry && boundedString(entry.device_id, 128)
      && inventory && inventory.schema_version === 1
      && Number.isSafeInteger(inventory.generated_at_unix_ms) && inventory.generated_at_unix_ms > 0
      && snapshotIsFresh(inventory.generated_at_unix_ms)
      && inventory.platform && boundedString(inventory.platform.os, 32)
      && (inventory.platform.os_version === null || inventory.platform.os_version === undefined || boundedString(inventory.platform.os_version, 64))
      && boundedString(inventory.platform.architecture, 32)
      && inventory.hardware
      && (inventory.hardware.cpu_logical_cores === null || Number.isSafeInteger(inventory.hardware.cpu_logical_cores) && inventory.hardware.cpu_logical_cores > 0 && inventory.hardware.cpu_logical_cores <= 65535)
      && (inventory.hardware.memory_total_mb === null || Number.isSafeInteger(inventory.hardware.memory_total_mb) && inventory.hardware.memory_total_mb > 0)
      && (inventory.hardware.memory_available_mb === null || Number.isSafeInteger(inventory.hardware.memory_available_mb) && inventory.hardware.memory_available_mb >= 0)
      && (inventory.hardware.memory_total_mb == null || inventory.hardware.memory_available_mb == null || inventory.hardware.memory_available_mb <= inventory.hardware.memory_total_mb)
      && (inventory.hardware.storage_free_mb === null || inventory.hardware.storage_free_mb === undefined || Number.isSafeInteger(inventory.hardware.storage_free_mb) && inventory.hardware.storage_free_mb >= 0)
      && Array.isArray(inventory.hardware.accelerators) && inventory.hardware.accelerators.length <= 32
      && inventory.hardware.accelerators.every((item) => item
        && ["gpu", "npu", "other"].includes(item.kind)
        && (item.vendor === null || item.vendor === undefined || boundedString(item.vendor, 64))
        && (item.device_family === null || item.device_family === undefined || boundedString(item.device_family, 96))
        && (item.memory_mb === null || item.memory_mb === undefined || Number.isSafeInteger(item.memory_mb) && item.memory_mb >= 0)
        && (item.runtime_api === null || item.runtime_api === undefined || boundedString(item.runtime_api, 64))
        && validEvidence(item.evidence))
      && (inventory.privacy === undefined || inventory.privacy && typeof inventory.privacy === "object" && !Array.isArray(inventory.privacy)
        && Object.keys(inventory.privacy).every((key) => ["contains_prompts", "contains_user_files", "contains_local_paths", "contains_credentials"].includes(key))
        && Object.values(inventory.privacy).every((value) => value === false))
      && Array.isArray(inventory.runtimes) && inventory.runtimes.length <= 16
      && inventory.runtimes.every((runtime) => runtime
        && boundedString(runtime.runtime_id, 96) && boundedString(runtime.provider, 64)
        && (runtime.version === null || boundedString(runtime.version, 64))
        && ["available", "unavailable", "unknown"].includes(runtime.availability)
        && ["loopback_only", "local_socket", "enterprise_internal", "not_applicable", "unknown"].includes(runtime.network_scope)
        && validEvidence(runtime.evidence))
      && new Set(inventory.runtimes.map((runtime) => runtime.runtime_id)).size === inventory.runtimes.length
      && Array.isArray(inventory.models) && inventory.models.length <= 512
      && inventory.models.every((model) => model
        && boundedString(model.model_ref, 160) && boundedString(model.runtime_id, 96)
        && boundedString(model.display_name, 160)
        && (model.family === null || model.family === undefined || boundedString(model.family, 96))
        && (model.version === null || model.version === undefined || boundedString(model.version, 64))
        && ["installed", "downloadable", "unavailable", "unknown"].includes(model.availability)
        && (model.size_bytes === null || Number.isSafeInteger(model.size_bytes) && model.size_bytes >= 0)
        && (model.context_length_tokens === null || model.context_length_tokens === undefined || Number.isSafeInteger(model.context_length_tokens) && model.context_length_tokens > 0)
        && (model.estimated_min_memory_mb === null || model.estimated_min_memory_mb === undefined || Number.isSafeInteger(model.estimated_min_memory_mb) && model.estimated_min_memory_mb >= 0)
        && Array.isArray(model.capabilities) && model.capabilities.length <= 16
        && new Set(model.capabilities).size === model.capabilities.length
        && model.capabilities.every((capability) => ["chat", "reasoning", "coding", "vision", "embeddings", "tool_use", "streaming", "audio_input", "audio_output", "unknown"].includes(capability))
        && validEvidence(model.evidence)
        && inventory.runtimes.some((runtime) => runtime.runtime_id === model.runtime_id))
      && new Set(inventory.models.map((model) => model.model_ref)).size === inventory.models.length;
  });
}
function renderModelInventory(inventories) {
  const body = byId("model-inventory");
  body.replaceChildren();
  const rows = [];
  let totalModels = 0;
  for (const entry of inventories || []) {
    const inventory = entry.inventory;
    for (const model of inventory.models) {
      totalModels += 1;
      if (rows.length < 5120) {
        const runtime = inventory.runtimes.find((item) => item.runtime_id === model.runtime_id);
        rows.push({ device_id: entry.device_id, inventory_at: inventory.generated_at_unix_ms, memory_available_mb: inventory.hardware.memory_available_mb, model, runtime });
      }
    }
  }
  byId("model-count").textContent = totalModels + " model records" + (totalModels > 5120 ? " · showing first 5,120" : "");
  if (!totalModels) {
    const row = document.createElement("tr");
    const cell = textCell("No authenticated model/runtime inventory is available.");
    cell.colSpan = 9; cell.className = "empty"; row.append(cell); body.append(row); return;
  }
  for (const item of rows.slice(0, 5120)) {
    const row = document.createElement("tr");
    row.append(textCell(item.device_id));
    row.append(textCell(item.model.display_name));
    row.append(textCell(item.model.version));
    row.append(textCell(item.model.family));
    row.append(textCell(item.runtime
      ? item.runtime.provider + " · " + (item.runtime.version || "version unknown") + " · " + item.runtime.availability + " · " + item.runtime.network_scope
      : item.model.runtime_id + " · runtime metadata unknown"));
    const availability = document.createElement("td"); availability.append(pill(item.model.availability)); row.append(availability);
    row.append(textCell(item.model.capabilities.join(", ")));
    const requiredRam = item.model.estimated_min_memory_mb;
    const ramFit = requiredRam == null || item.memory_available_mb == null
      ? "Unknown"
      : requiredRam <= item.memory_available_mb
        ? requiredRam + " MiB req / " + item.memory_available_mb + " MiB free · estimate fits"
        : requiredRam + " MiB req / " + item.memory_available_mb + " MiB free · insufficient";
    const fitCell = document.createElement("td"); fitCell.append(pill(ramFit)); row.append(fitCell);
    const evidenceAt = item.model.evidence.observed_at_unix_ms;
    const freshness = evidenceAt == null ? "Unknown" : snapshotIsFresh(evidenceAt) ? formatAge(evidenceAt) : "Stale";
    row.append(textCell(item.model.evidence.confidence + " · " + freshness));
    body.append(row);
  }
}
const MAX_OVERVIEW_RESPONSE_BYTES = 8 * 1024 * 1024;
const OVERVIEW_RESPONSE_LIMIT_LABEL = `${MAX_OVERVIEW_RESPONSE_BYTES / (1024 * 1024)} MiB`;
const MAX_OVERVIEW_SNAPSHOT_AGE_MS = 5 * 60 * 1000;
const MAX_OVERVIEW_CLOCK_SKEW_MS = 60 * 1000;

function snapshotIsFresh(generatedAtUnixMs, now = Date.now()) {
  if (!Number.isSafeInteger(generatedAtUnixMs) || generatedAtUnixMs <= 0) return false;
  const age = now - generatedAtUnixMs;
  return age >= -MAX_OVERVIEW_CLOCK_SKEW_MS && age <= MAX_OVERVIEW_SNAPSHOT_AGE_MS;
}

async function readBoundedJson(response) {
  const contentType = response.headers.get("content-type") || "";
  if (!/^application\/(?:[a-z0-9.+-]*\+)?json(?:\s*;|$)/i.test(contentType)) {
    throw new Error("The control plane did not return a JSON overview.");
  }
  const declaredLength = Number(response.headers.get("content-length"));
  if (Number.isFinite(declaredLength) && declaredLength > MAX_OVERVIEW_RESPONSE_BYTES) {
    throw new Error(`The control-plane overview exceeds the ${OVERVIEW_RESPONSE_LIMIT_LABEL} response limit.`);
  }
  if (!response.body || typeof response.body.getReader !== "function") {
    throw new Error("This browser cannot safely stream the bounded control-plane response.");
  }

  const reader = response.body.getReader();
  const chunks = [];
  let totalBytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      totalBytes += value.byteLength;
      if (totalBytes > MAX_OVERVIEW_RESPONSE_BYTES) {
        await reader.cancel();
        throw new Error(`The control-plane overview exceeds the ${OVERVIEW_RESPONSE_LIMIT_LABEL} response limit.`);
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new Error("The control plane returned malformed UTF-8 or JSON.");
  }
}

function validOverview(data) {
  const counts = data && data.fleet;
  const validCount = (value) => Number.isSafeInteger(value) && value >= 0;
  return data && data.schema_version === 1
    && typeof data.tenant_id === "string" && data.tenant_id.length > 0 && data.tenant_id.length <= 128
    && counts && validCount(counts.registered_devices)
    && validCount(counts.trusted_consented_devices)
    && validCount(counts.online_fresh_devices)
    && validCount(counts.schedulable_devices)
    && counts.registered_devices <= 10000
    && counts.trusted_consented_devices <= counts.registered_devices
    && counts.online_fresh_devices <= counts.trusted_consented_devices
    && counts.schedulable_devices <= counts.online_fresh_devices
    && Array.isArray(data.devices) && data.devices.length <= 10000
    && Array.isArray(data.workloads) && data.workloads.length <= 1000
    && Array.isArray(data.approvals) && data.approvals.length <= 1000
    && validModelInventory(data.model_inventory)
    && data.devices.length === counts.registered_devices
    && Number.isSafeInteger(data.generated_at_unix_ms) && data.generated_at_unix_ms > 0;
}
function renderOverview(data) {
  if (!validOverview(data)) throw new Error("The control plane returned an unsupported or incomplete overview schema.");
  if (!snapshotIsFresh(data.generated_at_unix_ms)) {
    throw new Error("The control plane overview is stale or has an invalid timestamp. Refresh after the service publishes a fresh snapshot.");
  }
  byId("registered").textContent = data.fleet.registered_devices.toLocaleString();
  byId("trusted").textContent = data.fleet.trusted_consented_devices.toLocaleString();
  byId("online").textContent = data.fleet.online_fresh_devices.toLocaleString();
  byId("schedulable").textContent = data.fleet.schedulable_devices.toLocaleString();
  renderDevices(data.devices);
  renderModelInventory(data.model_inventory);
  renderList("workloads", data.workloads, "No active workloads.", ["state", "class", "reason"]);
  renderList("approvals", data.approvals, "No pending approvals.", ["requester", "scope", "expires_at"]);
  byId("updated").textContent = "Snapshot: " + new Date(data.generated_at_unix_ms).toLocaleString();
  notice.hidden = true;
  setConnection("Connected · live snapshot", "online");
}
async function refreshOverview() {
  refreshButton.disabled = true;
  setConnection("Connecting…", "unknown");
  const controller = new AbortController();
  const requestTimeout = window.setTimeout(() => controller.abort(), 10_000);
  try {
    const response = await fetch(API_PATH, {
      method: "GET",
      credentials: "same-origin",
      cache: "no-store",
      redirect: "error",
      signal: controller.signal,
      headers: { "Accept": "application/json" }
    });
    if (response.status === 401 || response.status === 403) throw new Error("Sign in with an authorized Enterprise operator account to view this fleet.");
    if (response.status === 404) throw new Error("The Enterprise overview API is not deployed yet. No sample data is shown.");
    if (!response.ok) throw new Error("The control plane returned HTTP " + response.status + ".");
    const payload = await readBoundedJson(response);
    renderOverview(payload);
  } catch (error) {
    setConnection("Not connected", "error");
    notice.hidden = false;
    const heading = notice.querySelector("strong");
    const message = notice.querySelector("p");
    heading.textContent = "Live control-plane data unavailable";
    message.textContent = error instanceof Error && error.name === "AbortError"
      ? "The control-plane request exceeded the 10-second time limit."
      : error instanceof Error ? error.message : "Could not load the Enterprise overview.";
  } finally {
    window.clearTimeout(requestTimeout);
    refreshButton.disabled = false;
  }
}
refreshButton.addEventListener("click", refreshOverview);
setConnection("Control plane not connected", "unknown");
