import { readBoundedJson } from "./boundedJson.js";

const API_PATH = "/api/v1/operator/overview";
const MAX_MODEL_CATALOGUE_BYTES = 256 * 1024;
const byId = (id) => document.getElementById(id);
const connection = byId("connection");
const notice = byId("notice");
const refreshButton = byId("refresh");
const demoButton = byId("demo");
const demoBanner = byId("demo-banner");
const clockWarning = byId("clock-warning");
let serverTimeAnchorUnixMs = null;
let serverTimeAnchorMonotonicMs = null;
let demoMode = false;
let refreshInFlight = false;

function updateClockWarning(controlPlaneNowUnixMs) {
  const offsetMs = controlPlaneNowUnixMs - Date.now();
  if (Math.abs(offsetMs) > MAX_OVERVIEW_CLOCK_SKEW_MS) {
    const direction = offsetMs > 0 ? "behind" : "ahead";
    clockWarning.hidden = false;
    clockWarning.textContent = "This computer's clock is " + Math.round(Math.abs(offsetMs) / 1000)
      + " seconds " + direction + " the control-plane clock. Snapshot freshness is calculated from the control-plane time and a monotonic timer, not the computer's wall clock. Correct the operating-system time settings; UJANI will not change them.";
  } else {
    clockWarning.hidden = true;
    clockWarning.textContent = "";
  }
}

function trustedDisplayNow() {
  if (!Number.isFinite(serverTimeAnchorUnixMs) || !Number.isFinite(serverTimeAnchorMonotonicMs)
      || typeof performance === "undefined" || typeof performance.now !== "function") return null;
  const elapsed = performance.now() - serverTimeAnchorMonotonicMs;
  if (!Number.isFinite(elapsed) || elapsed < 0) return null;
  const trustedNow = serverTimeAnchorUnixMs + elapsed;
  updateClockWarning(trustedNow);
  return trustedNow;
}

function setServerTimeAnchor(serverTimeUnixMs) {
  if (!Number.isSafeInteger(serverTimeUnixMs) || serverTimeUnixMs <= 0) {
    throw new Error("The control plane did not provide a valid server-time reference.");
  }
  if (typeof performance === "undefined" || typeof performance.now !== "function"
      || !Number.isFinite(performance.now())) {
    throw new Error("A monotonic browser clock is unavailable; refresh the live snapshot in a supported browser.");
  }
  serverTimeAnchorUnixMs = serverTimeUnixMs;
  serverTimeAnchorMonotonicMs = performance.now();
  demoMode = false;
  updateClockWarning(serverTimeUnixMs);
}

function setConnection(label, state) {
  connection.textContent = label;
  connection.className = "status " + (state === "online" ? "status-online" : state === "error" ? "status-error" : "status-unknown");
}
function textCell(value) {
  const cell = document.createElement("td");
  cell.textContent = value == null || value === "" ? "—" : String(value);
  return cell;
}
function formatAge(timestamp, now = demoMode ? Date.now() : trustedDisplayNow()) {
  if (!Number.isFinite(timestamp) || timestamp <= 0 || !Number.isFinite(now)) return "Unknown";
  const age = Math.max(0, now - timestamp);
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
  if (["trusted", "enrolled", "available", "approved", "schedulable", "online", "current"].includes(normalized)) node.classList.add("pill-good");
  if (["stale", "busy", "pending", "sleeping", "paused", "attention", "unverified", "not_reported", "unknown", "not_monitored"].includes(normalized)) node.classList.add("pill-warn");
  if (["revoked", "rejected", "ineligible", "offline", "out_of_date", "alert"].includes(normalized)) node.classList.add("pill-bad");
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
function renderDemoModelInventory() {
  const body = byId("model-inventory");
  body.replaceChildren();
  const rows = [
    [
      "DEMO · Office workstation",
      "Qwen3 0.6B",
      "not pinned",
      "Qwen3",
      "Ollama",
      "available (demo)",
      "chat · classification",
      "CPU · 8 threads · 16 GiB RAM",
      "Advisory: 4 GiB RAM",
      "Synthetic / unverified"
    ],
    [
      "DEMO · GPU workstation",
      "Qwen3 4B",
      "not pinned",
      "Qwen3",
      "Ollama",
      "available (demo)",
      "chat · reasoning",
      "GPU observation · 32 GiB RAM",
      "Advisory: 12 GiB RAM",
      "Synthetic / unverified"
    ]
  ];
  for (const values of rows) {
    const row = document.createElement("tr");
    for (const value of values) row.append(textCell(value));
    body.append(row);
  }
  byId("model-count").textContent = rows.length + " synthetic rows";
}

function showDemoData() {
  demoMode = true;
  serverTimeAnchorUnixMs = null;
  serverTimeAnchorMonotonicMs = null;
  clockWarning.hidden = true;
  clockWarning.textContent = "";
  const now = Date.now();
  const devices = [
    {
      device_id: "demo-ws-01",
      display_name: "DEMO · Office workstation",
      platform: "Windows",
      trust_state: "enrolled",
      availability: "schedulable",
      remaining_cpu_millis: 4200,
      remaining_memory_mb: 12288,
      last_seen_unix_ms: now - 45_000
    },
    {
      device_id: "demo-ws-02",
      display_name: "DEMO · GPU workstation",
      platform: "Linux",
      trust_state: "enrolled",
      availability: "paused",
      remaining_cpu_millis: 6100,
      remaining_memory_mb: 24576,
      last_seen_unix_ms: now - 90_000
    },
    {
      device_id: "demo-srv-01",
      display_name: "DEMO · Internal server",
      platform: "Linux",
      trust_state: "enrolled",
      availability: "ineligible",
      remaining_cpu_millis: 9000,
      remaining_memory_mb: 32768,
      last_seen_unix_ms: now - 30_000
    }
  ];
  byId("registered").textContent = "3";
  byId("trusted").textContent = "3";
  byId("online").textContent = "3";
  byId("schedulable").textContent = "1";
  renderDevices(devices);
  byId("device-count").textContent = devices.length + " synthetic records";
  renderSecurityProviderInventory({
    schema_version: 1,
    generated_at_unix_ms: now,
    providers: [
      {
        device_id: "demo-ws-01", provider_id: "microsoft.defender", display_name: "DEMO · Microsoft Defender",
        category: "malware_protection", status: "healthy", evidence_freshness: "fresh", evidence_source: "Synthetic demo observation",
        observed_at_unix_ms: now - 30_000, evidence_max_age_ms: 60_000, product_identity_known: true,
        capabilities: ["malware_protection"], update_posture: "out_of_date",
        update_checked_at_unix_ms: now - 30_000, update_channel: "security_intelligence",
        update_recommendation: "DEMO ONLY: update the existing antivirus security intelligence through its vendor or OS workflow."
      },
      {
        device_id: "demo-ws-02", provider_id: "opnsense.firewall", display_name: "DEMO · OPNsense Firewall",
        category: "firewall", status: "healthy", evidence_freshness: "stale", evidence_source: "Synthetic demo observation",
        observed_at_unix_ms: now - 60_000, evidence_max_age_ms: 60_000, product_identity_known: true,
        capabilities: ["firewall"], update_posture: "unverified",
        update_checked_at_unix_ms: null, update_channel: null,
        update_recommendation: "DEMO ONLY: firewall update freshness cannot be verified."
      }
    ]
  });
  renderDemoModelInventory();
  renderList("workloads", [
    { title: "DEMO · Internal document summary", state: "queued", class: "internal", reason: "Waiting for a suitable approved worker" }
  ], "No demo workloads.", ["state", "class", "reason"]);
  renderList("approvals", [
    { title: "DEMO · Qwen3 4B candidate review", state: "pending", requester: "Demo operator", scope: "Catalogue review only", expires_at: "Not a real approval" }
  ], "No demo approvals.", ["requester", "scope", "expires_at"]);
  byId("updated").textContent = "DEMO SNAPSHOT · " + new Date(now).toLocaleString();
  notice.hidden = true;
  demoBanner.hidden = false;
  setConnection("DEMO DATA · not live", "unknown");
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


function renderModelCatalogue(catalogue) {
  const root = byId("model-catalogue");
  const taskFilter = byId("model-catalogue-task-filter");
  const selectedTask = taskFilter.value || "all";
  root.replaceChildren();
  if (!catalogue || catalogue.schema_version !== 1
      || !Array.isArray(catalogue.models) || catalogue.models.length > 64
      || !Array.isArray(catalogue.specialist_tools) || catalogue.specialist_tools.length > 32) {
    throw new Error("The local model catalogue has an unsupported structure.");
  }

  const availableTasks = new Set();
  for (const model of catalogue.models) {
    if (!model || !boundedString(model.id, 96) || !boundedString(model.display_name, 128)
        || !boundedString(model.purpose, 600) || !Array.isArray(model.tasks)
        || model.tasks.length > 32 || !model.tasks.every((task) => boundedString(task, 64))
        || new Set(model.tasks).size !== model.tasks.length
        || !Array.isArray(model.limitations) || !model.planning_ram_gib
        || !Number.isSafeInteger(model.planning_ram_gib.minimum)
        || !Number.isSafeInteger(model.planning_ram_gib.recommended)) {
      throw new Error("A model catalogue entry failed validation.");
    }
    for (const task of model.tasks) availableTasks.add(task);
  }

  taskFilter.replaceChildren();
  const allTasks = document.createElement("option");
  allTasks.value = "all";
  allTasks.textContent = "All tasks";
  taskFilter.append(allTasks);
  for (const task of [...availableTasks].sort()) {
    const option = document.createElement("option");
    option.value = task;
    option.textContent = task.replaceAll("_", " ");
    taskFilter.append(option);
  }
  taskFilter.value = availableTasks.has(selectedTask) ? selectedTask : "all";
  taskFilter.onchange = () => renderModelCatalogue(catalogue);

  const visibleModels = catalogue.models.filter((model) =>
    taskFilter.value === "all" || model.tasks.includes(taskFilter.value)
  );
  for (const model of visibleModels) {
    const card = document.createElement("article");
    card.className = "catalogue-card";
    const heading = document.createElement("h3");
    heading.textContent = model.display_name + " · " + model.publisher;
    const purpose = document.createElement("p");
    purpose.textContent = model.purpose;
    const tasks = document.createElement("p");
    tasks.textContent = "Useful for: " + model.tasks.join(", ").replaceAll("_", " ") + ".";
    const limits = document.createElement("p");
    limits.textContent = "Limitations: " + model.limitations.join(" ");
    const resources = document.createElement("p");
    resources.textContent = "RAM planning guide: " + model.planning_ram_gib.minimum + " GiB minimum / "
      + model.planning_ram_gib.recommended + " GiB recommended. This is advisory, not a fit guarantee.";
    const size = document.createElement("p");
    size.textContent = "Download and installed size: resolve from the exact quantised artifact before approval.";
    const licence = document.createElement("small");
    licence.textContent = "Licence: " + model.license;
    card.append(heading, purpose, tasks, limits, resources, size, licence);
    root.append(card);
  }
  const summary = document.createElement("p");
  summary.className = "muted";
  summary.textContent = "Showing " + visibleModels.length + " of " + catalogue.models.length
    + " candidate models. Task labels are catalogue metadata, not verified runtime capability.";
  root.append(summary);

  for (const tool of catalogue.specialist_tools) {
    if (!tool || !boundedString(tool.id, 96) || !boundedString(tool.display_name, 128)
        || !boundedString(tool.purpose, 600) || !Array.isArray(tool.limitations)) {
      throw new Error("A specialist tool catalogue entry failed validation.");
    }
    const card = document.createElement("article");
    card.className = "catalogue-card catalogue-specialist";
    const heading = document.createElement("h3");
    heading.textContent = tool.display_name + " · specialist tool";
    const purpose = document.createElement("p");
    purpose.textContent = tool.purpose;
    const limits = document.createElement("p");
    limits.textContent = "Limitations: " + tool.limitations.join(" ");
    card.append(heading, purpose, limits);
    root.append(card);
  }
}
async function loadModelCatalogue() {
  const root = byId("model-catalogue");
  const controller = new AbortController();
  const requestTimeout = window.setTimeout(() => controller.abort(), 5_000);
  try {
    const response = await fetch("./model-catalog.json", {
      method: "GET", credentials: "same-origin", cache: "no-store", redirect: "error",
      signal: controller.signal,
      headers: { "Accept": "application/json" }
    });
    if (!response.ok) throw new Error("Catalogue request returned HTTP " + response.status + ".");
    const catalogue = await readBoundedJson(response, MAX_MODEL_CATALOGUE_BYTES, "model catalogue");
    renderModelCatalogue(catalogue);
  } catch (error) {
    root.textContent = error instanceof Error && error.name === "AbortError"
      ? "Model catalogue unavailable: the request exceeded the 5-second time limit."
      : error instanceof Error ? "Model catalogue unavailable: " + error.message : "Model catalogue unavailable.";
    root.classList.add("empty");
  } finally {
    controller.abort();
    window.clearTimeout(requestTimeout);
  }
}

function boundedString(value, max) {
  return typeof value === "string" && value.length > 0 && value.length <= max;
}
function containsLocalPath(value) {
  if (typeof value !== "string") return false;
  if (value.toLowerCase().includes("file://")) return true;
  return value.split(/[\s=]+/).some((raw) => {
    const token = raw.replace(/^["'([{,;]+|["')\]},;]+$/g, "");
    return token.startsWith("/") || token.startsWith("~/")
      || token.startsWith("\\\\")
      || /^[A-Za-z]:[\\/]/.test(token);
  });
}
function validEvidence(evidence, generatedAtUnixMs) {
  const observedAt = evidence && evidence.observed_at_unix_ms;
  return evidence && ["runtime_api", "os_api", "runtime_metadata", "signed_catalogue", "published_catalogue", "estimate", "unknown"].includes(evidence.source)
    && ["verified", "reported", "estimated", "unknown"].includes(evidence.confidence)
    && !(evidence.source === "unknown" && evidence.confidence === "verified")
    && (observedAt === null || (Number.isSafeInteger(observedAt) && observedAt > 0
      && observedAt <= generatedAtUnixMs + MAX_INVENTORY_EVIDENCE_SKEW_MS));
}
function validModelInventory(entries) {
  if (entries === undefined) return true;
  if (!Array.isArray(entries) || entries.length > 10000) return false;
  let totalModels = 0;
  for (const entry of entries) {
    const models = entry && entry.inventory && entry.inventory.models;
    if (!Array.isArray(models)) return false;
    totalModels += models.length;
    if (totalModels > MAX_TOTAL_MODEL_ROWS) return false;
  }
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
        && validEvidence(item.evidence, inventory.generated_at_unix_ms))
      && (inventory.privacy === undefined || inventory.privacy && typeof inventory.privacy === "object" && !Array.isArray(inventory.privacy)
        && Object.keys(inventory.privacy).every((key) => ["contains_prompts", "contains_user_files", "contains_local_paths", "contains_credentials"].includes(key))
        && Object.values(inventory.privacy).every((value) => value === false))
      && Array.isArray(inventory.runtimes) && inventory.runtimes.length <= 16
      && inventory.runtimes.every((runtime) => runtime
        && boundedString(runtime.runtime_id, 96) && boundedString(runtime.provider, 64)
        && (runtime.version === null || boundedString(runtime.version, 64))
        && ["available", "unavailable", "unknown"].includes(runtime.availability)
        && ["loopback_only", "local_socket", "enterprise_internal", "not_applicable", "unknown"].includes(runtime.network_scope)
        && validEvidence(runtime.evidence, inventory.generated_at_unix_ms))
      && new Set(inventory.runtimes.map((runtime) => runtime.runtime_id)).size === inventory.runtimes.length
      && Array.isArray(inventory.models) && inventory.models.length <= 512
      && inventory.models.every((model) => model
        && boundedString(model.model_ref, 160) && !containsLocalPath(model.model_ref)
        && boundedString(model.runtime_id, 96)
        && boundedString(model.display_name, 160) && !containsLocalPath(model.display_name)
        && (model.family === null || model.family === undefined || boundedString(model.family, 96))
        && (model.version === null || model.version === undefined || boundedString(model.version, 64))
        && ["installed", "downloadable", "unavailable", "unknown"].includes(model.availability)
        && (model.size_bytes === null || Number.isSafeInteger(model.size_bytes) && model.size_bytes >= 0)
        && (model.context_length_tokens === null || model.context_length_tokens === undefined || Number.isSafeInteger(model.context_length_tokens) && model.context_length_tokens > 0)
        && (model.estimated_min_memory_mb === null || model.estimated_min_memory_mb === undefined
          || Number.isSafeInteger(model.estimated_min_memory_mb) && model.estimated_min_memory_mb > 0
          && model.estimated_min_memory_mb <= MAX_MODEL_MEMORY_ESTIMATE_MB)
        && Array.isArray(model.capabilities) && model.capabilities.length <= 16
        && new Set(model.capabilities).size === model.capabilities.length
        && model.capabilities.every((capability) => ["chat", "reasoning", "coding", "vision", "embeddings", "tool_use", "streaming", "audio_input", "audio_output", "unknown"].includes(capability))
        && validEvidence(model.evidence, inventory.generated_at_unix_ms)
        && inventory.runtimes.some((runtime) => runtime.runtime_id === model.runtime_id))
      && new Set(inventory.models.map((model) => model.model_ref)).size === inventory.models.length;
  });
}
function formatMiB(value) {
  return value == null ? "Unknown" : Math.round(value).toLocaleString() + " MiB";
}
function evidenceSummary(evidence) {
  if (!evidence) return "Unknown";
  const observedAt = evidence.observed_at_unix_ms;
  const freshness = observedAt == null ? "Unknown" : snapshotIsFresh(observedAt) ? "Fresh" : "Stale";
  return (evidence.confidence || "Unknown") + " · " + freshness;
}
function runtimeSummary(runtimes) {
  if (!runtimes || !runtimes.length) return "Runtime not reported";
  return runtimes.map((runtime) =>
    runtime.provider + " " + (runtime.version || "version unknown")
      + " · " + runtime.availability + " · " + runtime.network_scope
  ).join("; ");
}
function runtimeEvidenceSummary(runtimes) {
  if (!runtimes || !runtimes.length) return "Runtime: Unknown";
  return runtimes.map((runtime) =>
    runtime.runtime_id + ": " + evidenceSummary(runtime.evidence)
  ).join("; ");
}
function hardwareSummary(inventory) {
  const hardware = inventory.hardware;
  const parts = [
    "CPU " + (hardware.cpu_logical_cores == null ? "unknown" : hardware.cpu_logical_cores + " logical cores"),
    "RAM " + formatMiB(hardware.memory_available_mb) + " free / " + formatMiB(hardware.memory_total_mb) + " total",
    "Storage " + formatMiB(hardware.storage_free_mb) + " free"
  ];
  if (!hardware.accelerators.length) {
    parts.push("Accelerators not reported");
  } else {
    for (const accelerator of hardware.accelerators) {
      const label = [
        String(accelerator.kind).toUpperCase(),
        accelerator.vendor || "vendor unknown",
        accelerator.device_family || "family unknown"
      ].join(" ");
      parts.push(label + " · " + formatMiB(accelerator.memory_mb)
        + " · " + evidenceSummary(accelerator.evidence));
    }
  }
  parts.push("Snapshot " + formatAge(inventory.generated_at_unix_ms));
  return parts.join(" · ");
}
function renderModelInventory(inventories, overview) {
  const body = byId("model-inventory");
  body.replaceChildren();
  const rows = [];
  let returnedModels = 0;
  for (const entry of inventories || []) {
    const inventory = entry.inventory;
    if (!inventory.models.length) {
      if (rows.length < 5120) rows.push({ device_id: entry.device_id, inventory, model: null, runtime: null });
      continue;
    }
    for (const model of inventory.models) {
      returnedModels += 1;
      if (rows.length < 5120) {
        const runtime = inventory.runtimes.find((item) => item.runtime_id === model.runtime_id);
        rows.push({ device_id: entry.device_id, inventory, model, runtime });
      }
    }
  }
  const totalModels = overview.model_inventory_total_models;
  let countLabel = totalModels.toLocaleString() + " model records across "
    + overview.model_inventory_total_devices.toLocaleString() + " devices";
  if (overview.model_inventory_status === "partial_response_budget") {
    countLabel += " · response budget limited; " + returnedModels.toLocaleString()
      + " models from " + overview.model_inventory_returned_devices.toLocaleString() + " devices returned";
  }
  const renderedModels = rows.filter((item) => item.model).length;
  if (returnedModels > renderedModels) {
    countLabel += " · showing " + renderedModels.toLocaleString()
      + " of " + returnedModels.toLocaleString() + " returned model rows";
  }
  const renderedDevices = new Set(rows.map((item) => item.device_id)).size;
  if (renderedDevices < overview.model_inventory_returned_devices) {
    countLabel += " · showing " + renderedDevices.toLocaleString() + " device inventories";
  }
  byId("model-count").textContent = countLabel;
  if (!inventories || !inventories.length) {
    const row = document.createElement("tr");
    const message = overview.model_inventory_status === "partial_response_budget"
      ? "The response budget did not fit a complete device inventory; retry with a narrower fleet filter."
      : "No authenticated model/runtime inventory has been reported by authorised devices.";
    const cell = textCell(message);
    cell.colSpan = 10; cell.className = "empty"; row.append(cell); body.append(row); return;
  }
  for (const item of rows) {
    const row = document.createElement("tr");
    row.append(textCell(item.device_id));
    if (!item.model) {
      row.append(textCell("No model metadata reported"));
      row.append(textCell(null));
      row.append(textCell(null));
      row.append(textCell(runtimeSummary(item.inventory.runtimes)));
      const availability = document.createElement("td"); availability.append(pill("unknown")); row.append(availability);
      row.append(textCell("Not reported"));
      row.append(textCell(hardwareSummary(item.inventory)));
      const fitCell = document.createElement("td"); fitCell.append(pill("Unknown")); row.append(fitCell);
      row.append(textCell("Model: Not reported · " + runtimeEvidenceSummary(item.inventory.runtimes)));
      body.append(row);
      continue;
    }
    row.append(textCell(item.model.display_name));
    row.append(textCell(item.model.version));
    row.append(textCell(item.model.family));
    row.append(textCell(item.runtime
      ? runtimeSummary([item.runtime])
      : item.model.runtime_id + " · runtime metadata unknown"));
    const availability = document.createElement("td"); availability.append(pill(item.model.availability)); row.append(availability);
    row.append(textCell(item.model.capabilities.join(", ")));
    row.append(textCell(hardwareSummary(item.inventory)));
    const requiredRam = item.model.estimated_min_memory_mb;
    const availableRam = item.inventory.hardware.memory_available_mb;
    const ramFit = requiredRam == null || availableRam == null
      ? "Unknown"
      : requiredRam <= availableRam
        ? requiredRam + " MiB req / " + availableRam + " MiB free · estimate fits"
        : requiredRam + " MiB req / " + availableRam + " MiB free · insufficient";
    const fitCell = document.createElement("td"); fitCell.append(pill(ramFit)); row.append(fitCell);
    row.append(textCell("Model: " + evidenceSummary(item.model.evidence)
      + " · Runtime: " + evidenceSummary(item.runtime && item.runtime.evidence)));
    body.append(row);
  }
}
const MAX_OVERVIEW_RESPONSE_BYTES = 8 * 1024 * 1024;
const OVERVIEW_RESPONSE_LIMIT_LABEL = `${MAX_OVERVIEW_RESPONSE_BYTES / (1024 * 1024)} MiB`;
const MAX_OVERVIEW_SNAPSHOT_AGE_MS = 5 * 60 * 1000;
const MAX_OVERVIEW_CLOCK_SKEW_MS = 60 * 1000;
const MAX_INVENTORY_EVIDENCE_SKEW_MS = 30 * 1000;
const MAX_MODEL_MEMORY_ESTIMATE_MB = 16_777_216;
const MAX_TOTAL_MODEL_ROWS = 100_000;

function snapshotIsFresh(generatedAtUnixMs, now = trustedDisplayNow()) {
  if (!Number.isSafeInteger(generatedAtUnixMs) || generatedAtUnixMs <= 0 || !Number.isFinite(now)) return false;
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

function validSecurityProviderInventory(inventory, overviewGeneratedAt, devices) {
  if (inventory === undefined) return true;
  if (!inventory || inventory.schema_version !== 1
      || !Number.isSafeInteger(inventory.generated_at_unix_ms) || inventory.generated_at_unix_ms <= 0
      || inventory.generated_at_unix_ms > overviewGeneratedAt + MAX_INVENTORY_EVIDENCE_SKEW_MS
      || !snapshotIsFresh(inventory.generated_at_unix_ms)
      || !Array.isArray(inventory.providers) || inventory.providers.length > 10000) return false;
  const deviceIds = new Set(devices.map((device) => device.device_id));
  const ids = new Set();
  return inventory.providers.every((item) => {
    if (!item || !boundedString(item.device_id, 128)
        || !deviceIds.has(item.device_id)
        || !boundedString(item.provider_id, 96)
        || !["malware_protection", "firewall", "endpoint_detection_response", "quarantine", "device_isolation", "security_updates"].includes(item.category)
        || !["healthy", "attention", "alert", "not_monitored", "unavailable", "unknown"].includes(item.status)
        || !["fresh", "stale", "unknown"].includes(item.evidence_freshness)
        || !Number.isSafeInteger(item.evidence_max_age_ms) || item.evidence_max_age_ms <= 0 || item.evidence_max_age_ms > 2592000000
        || (item.evidence_freshness === "fresh"
          && (inventory.generated_at_unix_ms - item.observed_at_unix_ms < -MAX_INVENTORY_EVIDENCE_SKEW_MS
            || inventory.generated_at_unix_ms - item.observed_at_unix_ms > item.evidence_max_age_ms))
        || (item.evidence_freshness === "stale"
          && inventory.generated_at_unix_ms - item.observed_at_unix_ms <= item.evidence_max_age_ms)
        || !boundedString(item.evidence_source, 128)
        || !Number.isSafeInteger(item.observed_at_unix_ms) || item.observed_at_unix_ms <= 0
        || item.observed_at_unix_ms > inventory.generated_at_unix_ms + MAX_INVENTORY_EVIDENCE_SKEW_MS
        || typeof item.product_identity_known !== "boolean"
        || !Array.isArray(item.capabilities) || item.capabilities.length > 32
        || !item.capabilities.every((capability) => boundedString(capability, 96))
        || new Set(item.capabilities).size !== item.capabilities.length
        || !["current", "out_of_date", "unverified", "not_reported"].includes(item.update_posture)
        || !(item.update_checked_at_unix_ms === null
          || Number.isSafeInteger(item.update_checked_at_unix_ms) && item.update_checked_at_unix_ms > 0
            && item.update_checked_at_unix_ms <= inventory.generated_at_unix_ms + MAX_INVENTORY_EVIDENCE_SKEW_MS
            && item.update_checked_at_unix_ms <= item.observed_at_unix_ms + MAX_INVENTORY_EVIDENCE_SKEW_MS
            && trustedDisplayNow() - item.update_checked_at_unix_ms >= -MAX_INVENTORY_EVIDENCE_SKEW_MS
            && trustedDisplayNow() - item.update_checked_at_unix_ms <= item.evidence_max_age_ms)
        || (item.update_posture === "current"
          && (item.update_checked_at_unix_ms === null
            || inventory.generated_at_unix_ms - item.update_checked_at_unix_ms > item.evidence_max_age_ms))
        || (item.evidence_freshness !== "fresh" && ["current", "out_of_date"].includes(item.update_posture))
        || (item.update_posture === "not_reported" && item.update_checked_at_unix_ms !== null)
        || !(item.display_name === null || boundedString(item.display_name, 160))
        || !(item.update_channel === null || boundedString(item.update_channel, 160))
        || !boundedString(item.update_recommendation, 512)) return false;
    const key = JSON.stringify([item.device_id, item.provider_id, item.category]);
    if (ids.has(key)) return false;
    ids.add(key);
    return true;
  });
}
function renderSecurityProviderInventory(inventory) {
  const body = byId("security-provider-inventory");
  body.replaceChildren();
  const providers = inventory && Array.isArray(inventory.providers) ? inventory.providers : [];
  byId("security-provider-count").textContent = inventory
    ? providers.length + " provider records"
    : "Not reported";
  if (!providers.length) {
    const row = document.createElement("tr");
    const cell = textCell("No authenticated security-provider evidence is available. Configure an approved read-only OS/vendor connector; UJANI will not install or change security software.");
    cell.colSpan = 8;
    cell.className = "empty";
    row.append(cell);
    body.append(row);
    return;
  }
  for (const item of providers) {
    const row = document.createElement("tr");
    row.append(textCell(item.device_id));
    const providerCell = document.createElement("td");
    const providerName = document.createElement("div");
    providerName.textContent = item.display_name || item.provider_id;
    const identityNote = document.createElement("small");
    identityNote.textContent = item.product_identity_known ? "Product identity reported" : "Product identity not verified";
    providerCell.append(providerName, identityNote);
    row.append(providerCell);
    row.append(textCell(item.category.replaceAll("_", " ")));
    const health = document.createElement("td");
    const reportedHealth = item.evidence_freshness === "fresh" ? item.status : item.evidence_freshness;
    health.append(pill(reportedHealth));
    if (item.evidence_freshness !== "fresh") {
      const note = document.createElement("small");
      note.textContent = "Provider health is not treated as current because this evidence is " + item.evidence_freshness + ".";
      health.append(note);
    }
    if (item.evidence_freshness === "fresh" && (item.status === "alert" || item.status === "attention")) {
      const note = document.createElement("small");
      note.textContent = "Review the alert in the existing security product.";
      health.append(note);
    }
    row.append(health);
    const updates = document.createElement("td");
    updates.append(pill(item.update_posture));
    const checked = document.createElement("small");
    checked.textContent = item.update_checked_at_unix_ms === null
      ? "Update check not reported"
      : "Checked " + formatAge(item.update_checked_at_unix_ms)
        + (item.update_channel ? " · " + item.update_channel : "");
    updates.append(checked);
    if (item.update_posture === "out_of_date" || item.update_posture === "unverified" || item.update_posture === "not_reported") {
      const note = document.createElement("small");
      note.textContent = item.update_recommendation;
      updates.append(note);
    }
    const updateEvidence = document.createElement("small");
    const checkedAge = formatAge(item.update_checked_at_unix_ms);
    const channel = typeof item.update_channel === "string" && item.update_channel.length > 0
      ? item.update_channel
      : "channel not reported";
    updateEvidence.textContent = "Update evidence: " + checkedAge + " · " + channel;
    updates.append(updateEvidence);
    row.append(updates);
    row.append(textCell(item.capabilities.join(", ") || "Not reported"));
    row.append(textCell(item.evidence_source));
    const observed = document.createElement("td");
    const observedAge = document.createElement("div");
    observedAge.textContent = formatAge(item.observed_at_unix_ms);
    const freshnessLimit = document.createElement("small");
    const freshnessLimitLabel = item.evidence_max_age_ms < 3_600_000
      ? Math.max(1, Math.round(item.evidence_max_age_ms / 60_000)) + "m"
      : Math.max(1, Math.round(item.evidence_max_age_ms / 3_600_000)) + "h";
    freshnessLimit.textContent = "Freshness limit: " + freshnessLimitLabel;
    observed.append(observedAge, freshnessLimit);
    row.append(observed);
    body.append(row);
  }
}

function validOverview(data) {
  const counts = data && data.fleet;
  const validCount = (value) => Number.isSafeInteger(value) && value >= 0;
  const returnedModelCount = Array.isArray(data && data.model_inventory)
    ? data.model_inventory.reduce((total, entry) => total
      + (entry && entry.inventory && Array.isArray(entry.inventory.models) ? entry.inventory.models.length : 0), 0)
    : data && data.model_inventory === undefined ? 0 : -1;
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
    && (data.model_inventory === undefined || Array.isArray(data.model_inventory) && validModelInventory(data.model_inventory))
    && validCount(data.model_inventory_total_devices) && data.model_inventory_total_devices <= 10000
    && validCount(data.model_inventory_returned_devices)
    && data.model_inventory_returned_devices === (data.model_inventory || []).length
    && data.model_inventory_total_devices >= data.model_inventory_returned_devices
    && validCount(data.model_inventory_total_models) && data.model_inventory_total_models <= MAX_TOTAL_MODEL_ROWS
    && validCount(data.model_inventory_returned_models)
    && data.model_inventory_returned_models === returnedModelCount
    && data.model_inventory_total_models >= data.model_inventory_returned_models
    && ["complete", "partial_response_budget"].includes(data.model_inventory_status)
    && (data.model_inventory_status === "complete"
      ? data.model_inventory_total_devices === data.model_inventory_returned_devices
        && data.model_inventory_total_models === data.model_inventory_returned_models
      : data.model_inventory_total_devices > data.model_inventory_returned_devices
        || data.model_inventory_total_models > data.model_inventory_returned_models)
    && data.devices.length === counts.registered_devices
    && Number.isSafeInteger(data.generated_at_unix_ms) && data.generated_at_unix_ms > 0
    && Number.isSafeInteger(data.server_time_unix_ms) && data.server_time_unix_ms > 0
    && validSecurityProviderInventory(data.security_provider_inventory, data.generated_at_unix_ms, data.devices);
}
function renderOverview(data) {
  if (!data || !Number.isSafeInteger(data.server_time_unix_ms) || data.server_time_unix_ms <= 0) {
    throw new Error("The control plane response is missing its trusted server-time reference. Refresh after the service is upgraded.");
  }
  setServerTimeAnchor(data.server_time_unix_ms);
  if (!validOverview(data)) throw new Error("The control plane returned an unsupported or incomplete overview schema.");
  if (!snapshotIsFresh(data.generated_at_unix_ms)) {
    throw new Error("The control plane overview is stale or has an invalid timestamp. Refresh after the service publishes a fresh snapshot.");
  }
  byId("registered").textContent = data.fleet.registered_devices.toLocaleString();
  byId("trusted").textContent = data.fleet.trusted_consented_devices.toLocaleString();
  byId("online").textContent = data.fleet.online_fresh_devices.toLocaleString();
  byId("schedulable").textContent = data.fleet.schedulable_devices.toLocaleString();
  renderDevices(data.devices);
  renderSecurityProviderInventory(data.security_provider_inventory || null);
  renderModelInventory(data.model_inventory || [], data);
  renderList("workloads", data.workloads, "No active workloads.", ["state", "class", "reason"]);
  renderList("approvals", data.approvals, "No pending approvals.", ["requester", "scope", "expires_at"]);
  byId("updated").textContent = "Snapshot: " + new Date(data.generated_at_unix_ms).toLocaleString();
  notice.hidden = true;
  setConnection("Connected · live snapshot", "online");
}
function clearOverview() {
  demoMode = false;
  serverTimeAnchorUnixMs = null;
  serverTimeAnchorMonotonicMs = null;
  clockWarning.hidden = true;
  clockWarning.textContent = "";
  demoBanner.hidden = true;
  for (const id of ["registered", "trusted", "online", "schedulable"]) {
    byId(id).textContent = "—";
  }
  byId("updated").textContent = "No current live snapshot";
  renderDevices([]);
  renderSecurityProviderInventory(null);
  byId("model-count").textContent = "No current inventory";
  const modelBody = byId("model-inventory");
  modelBody.replaceChildren();
  const modelRow = document.createElement("tr");
  const modelCell = textCell("No current authenticated model inventory available.");
  modelCell.colSpan = 10;
  modelCell.className = "empty";
  modelRow.append(modelCell);
  modelBody.append(modelRow);
  renderList("workloads", [], "No current workload data.", []);
  renderList("approvals", [], "No current approval data.", []);
}

async function refreshOverview() {
  if (refreshInFlight) return;
  refreshInFlight = true;
  refreshButton.disabled = true;
  demoButton.disabled = true;
  clearOverview();
  notice.hidden = false;
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
    clearOverview();
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
    refreshInFlight = false;
    refreshButton.disabled = false;
    demoButton.disabled = false;
  }
}
function refreshAfterResume() {
  if (demoMode || refreshInFlight) return;
  void refreshOverview();
}
document.addEventListener("visibilitychange", () => {
  if (!document.hidden) refreshAfterResume();
});
window.addEventListener("focus", refreshAfterResume);
demoButton.addEventListener("click", showDemoData);
refreshButton.addEventListener("click", refreshOverview);
setConnection("Control plane not connected", "unknown");
loadModelCatalogue();
