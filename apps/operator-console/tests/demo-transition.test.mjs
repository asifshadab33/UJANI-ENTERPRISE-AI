import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

async function readAppSource() {
  const source = await readFile(new URL("../app.js", import.meta.url), "utf8");
  return source.replace(/^import \{ readBoundedJson as readBoundedCatalogueJson \} from "\.\/boundedJson\.js";\s*/u, "");
}


class FakeElement {
  constructor() {
    this.textContent = "";
    this.value = "";
    this.children = [];
    this.hidden = false;
    this.disabled = false;
    this.className = "";
    this.classList = {
      add: () => {},
      remove: () => {}
    };
    this.listeners = {};
  }

  append(...nodes) {
    this.children.push(...nodes);
  }

  replaceChildren(...nodes) {
    this.children = [...nodes];
  }

  addEventListener(name, callback) {
    this.listeners[name] = callback;
  }
}

function collectText(element) {
  return [
    element.textContent,
    ...element.children.map((child) => collectText(child))
  ].filter(Boolean).join(" ");
}

test("live refresh clears synthetic demo data before the API request resolves", async () => {
  const source = await readAppSource();
  const elements = new Map();
  const getElement = (id) => {
    if (!elements.has(id)) elements.set(id, new FakeElement());
    return elements.get(id);
  };

  const heading = new FakeElement();
  const message = new FakeElement();
  getElement("notice").querySelector = (selector) =>
    selector === "strong" ? heading : message;

  let resolveLiveRequest;
  const requestedUrls = [];
  const requestOptions = [];
  const fetchMock = (url, options = {}) => {
    requestedUrls.push(url);
    requestOptions.push({ url, options });
    if (url === "./model-catalog.json") {
      return Promise.reject(new Error("test fixture: catalogue not loaded"));
    }
    if (url === "/api/v1/operator/overview") {
      return new Promise((resolve) => {
        resolveLiveRequest = resolve;
      });
    }
    throw new Error("Unexpected network request: " + url);
  };

  const context = vm.createContext({
    document: {
      getElementById: getElement,
      createElement: () => new FakeElement(),
      addEventListener: () => {},
      hidden: false
    },
    window: {
      setTimeout: () => 1,
      clearTimeout: () => {},
      addEventListener: () => {}
    },
    fetch: fetchMock,
    AbortController,
    console
  });

  vm.runInContext(source, context);
  await new Promise((resolve) => setImmediate(resolve));

  vm.runInContext("showDemoData()", context);
  assert.equal(getElement("demo-banner").hidden, false);
  assert.match(collectText(getElement("devices")), /DEMO/);
  assert.match(collectText(getElement("model-inventory")), /DEMO/);
  assert.match(collectText(getElement("workloads")), /DEMO/);
  assert.match(collectText(getElement("approvals")), /DEMO/);

  const refreshPromise = vm.runInContext("refreshOverview()", context);
  assert.equal(typeof resolveLiveRequest, "function");
  assert.ok(requestedUrls.includes("/api/v1/operator/overview"));
  const liveRequest = requestOptions.find((request) => request.url === "/api/v1/operator/overview");
  assert.ok(liveRequest, "the live overview request must be observable in the test");
  assert.equal(liveRequest.options.method, "GET");
  assert.equal(liveRequest.options.credentials, "same-origin", "operator session credentials must stay same-origin");
  assert.equal(liveRequest.options.cache, "no-store", "fleet snapshots must not be served from a browser cache");
  assert.equal(liveRequest.options.redirect, "error", "the authenticated overview request must not follow redirects");
  assert.equal(liveRequest.options.headers.Accept, "application/json");
  assert.ok(liveRequest.options.signal instanceof AbortSignal, "the live request must be cancellable");

  // refreshOverview executes synchronously through clearOverview() before
  // awaiting fetch(). Synthetic records must already be gone at this point.
  assert.equal(getElement("demo-banner").hidden, true);
  assert.equal(getElement("registered").textContent, "—");
  assert.doesNotMatch(collectText(getElement("devices")), /DEMO/);
  assert.doesNotMatch(collectText(getElement("model-inventory")), /DEMO/);
  assert.doesNotMatch(collectText(getElement("workloads")), /DEMO/);
  assert.doesNotMatch(collectText(getElement("approvals")), /DEMO/);
  assert.equal(getElement("demo").disabled, true);

  resolveLiveRequest({ status: 404, ok: false });
  await refreshPromise;
  assert.equal(getElement("demo-banner").hidden, true);
  assert.equal(getElement("demo").disabled, false);
  assert.match(message.textContent, /API is not deployed yet/);
});


test("live snapshot freshness uses server time plus a monotonic clock, not the local wall clock", async () => {
  const source = await readAppSource();
  const elements = new Map();
  const getElement = (id) => {
    if (!elements.has(id)) elements.set(id, new FakeElement());
    return elements.get(id);
  };
  let localWallNow = 1_000_000;
  let monotonicNow = 100;
  class TestDate extends Date {
    static now() { return localWallNow; }
  }
  const context = vm.createContext({
    document: { getElementById: getElement, createElement: () => new FakeElement(), addEventListener: () => {}, hidden: false },
    window: { setTimeout: () => 1, clearTimeout: () => {}, addEventListener: () => {} },
    fetch: async () => ({ ok: false, status: 404 }),
    AbortController,
    Date: TestDate,
    performance: { now: () => monotonicNow },
    console
  });
  vm.runInContext(source, context);
  vm.runInContext("setServerTimeAnchor(2_000_000)", context);
  assert.equal(vm.runInContext("snapshotIsFresh(1_880_000)", context), true);
  assert.equal(getElement("clock-warning").hidden, false);
  assert.match(getElement("clock-warning").textContent, /clock is 1000 seconds behind/);
  assert.equal(vm.runInContext("formatAge(1_880_000)", context), "2 min ago");

  // A large local wall-clock correction must not change the anchored server time.
  localWallNow = 9_000_000;
  monotonicNow += 120_000;
  assert.equal(vm.runInContext("snapshotIsFresh(1_880_000)", context), true);
  assert.equal(vm.runInContext("formatAge(1_880_000)", context), "4 min ago");
  assert.match(getElement("clock-warning").textContent, /clock is 6880 seconds ahead/);

  monotonicNow += 200_001;
  assert.equal(vm.runInContext("snapshotIsFresh(1_880_000)", context), false);
});


test("console refreshes live data after resume but preserves explicitly selected demo mode", async () => {
  const source = await readAppSource();
  const elements = new Map();
  const getElement = (id) => {
    if (!elements.has(id)) elements.set(id, new FakeElement());
    return elements.get(id);
  };
  const documentListeners = {};
  const windowListeners = {};
  let liveRequests = 0;
  const heading = new FakeElement();
  const message = new FakeElement();
  getElement("notice").querySelector = (selector) => selector === "strong" ? heading : message;

  const context = vm.createContext({
    document: {
      hidden: false,
      getElementById: getElement,
      createElement: () => new FakeElement(),
      addEventListener: (name, callback) => { documentListeners[name] = callback; }
    },
    window: {
      setTimeout: () => 1,
      clearTimeout: () => {},
      addEventListener: (name, callback) => { windowListeners[name] = callback; }
    },
    fetch: async (url) => {
      if (url === "./model-catalog.json") throw new Error("catalogue not loaded");
      if (url === "/api/v1/operator/overview") {
        liveRequests += 1;
        return { status: 404, ok: false };
      }
      throw new Error("Unexpected network request: " + url);
    },
    AbortController,
    console
  });

  vm.runInContext(source, context);
  await new Promise((resolve) => setImmediate(resolve));
  vm.runInContext("showDemoData()", context);

  windowListeners.focus();
  documentListeners.visibilitychange();
  assert.equal(liveRequests, 0, "explicit demo mode must not be cleared by focus/resume");

  vm.runInContext("clearOverview()", context);
  windowListeners.focus();
  assert.equal(liveRequests, 1, "returning to a live console refreshes the server snapshot");
  documentListeners.visibilitychange();
  assert.equal(liveRequests, 1, "focus and visibility events must not start overlapping requests");

  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(getElement("demo-banner").hidden, true);
  assert.match(message.textContent, /API is not deployed yet/);
});

test("security-provider inventory enforces device binding and conservative freshness", async () => {
  const source = await readAppSource();
  const elements = new Map();
  const getElement = (id) => {
    if (!elements.has(id)) elements.set(id, new FakeElement());
    return elements.get(id);
  };
  class TestDate extends Date {
    static now() { return 1_000_000; }
  }
  const context = vm.createContext({
    document: {
      getElementById: getElement,
      createElement: () => new FakeElement(),
      addEventListener: () => {},
      hidden: false
    },
    window: { setTimeout: () => 1, clearTimeout: () => {}, addEventListener: () => {} },
    fetch: async (url) => url === "./model-catalog.json"
      ? Promise.reject(new Error("test fixture: catalogue unavailable"))
      : ({ ok: false, status: 404 }),
    AbortController,
    Date: TestDate,
    performance: { now: () => 0 },
    console
  });
  vm.runInContext(source, context);
  await new Promise((resolve) => setImmediate(resolve));
  vm.runInContext("setServerTimeAnchor(1000000)", context);

  const validProvider = {
    device_id: "device-1",
    provider_id: "vendor.edr",
    display_name: "Existing Endpoint Protection",
    category: "malware_protection",
    status: "healthy",
    evidence_source: "ReadOnlyConnector",
    evidence_freshness: "fresh",
    evidence_max_age_ms: 60_000,
    observed_at_unix_ms: 999_000,
    product_identity_known: true,
    capabilities: ["malware_protection"],
    update_posture: "out_of_date",
    update_checked_at_unix_ms: 999_000,
    update_channel: "security_intelligence",
    update_recommendation: "Update through the existing vendor workflow."
  };
  context.inventory = {
    schema_version: 1,
    generated_at_unix_ms: 1_000_000,
    providers: [validProvider]
  };
  context.devices = [{ device_id: "device-1" }];
  assert.equal(
    vm.runInContext("validSecurityProviderInventory(inventory, 1000000, devices)", context),
    true
  );

  context.inventory.providers[0] = { ...validProvider, device_id: "untrusted-device" };
  assert.equal(
    vm.runInContext("validSecurityProviderInventory(inventory, 1000000, devices)", context),
    false
  );

  context.inventory.providers[0] = { ...validProvider, observed_at_unix_ms: 1 };
  assert.equal(
    vm.runInContext("validSecurityProviderInventory(inventory, 1000000, devices)", context),
    false
  );

  context.inventory.providers[0] = {
    ...validProvider,
    evidence_max_age_ms: 24 * 60 * 60 * 1000,
    observed_at_unix_ms: 100_000,
    update_checked_at_unix_ms: 100_000
  };
  assert.equal(
    vm.runInContext("validSecurityProviderInventory(inventory, 1000000, devices)", context),
    true,
    "freshness must use the provider's configured age, not a universal five-minute window"
  );

  context.inventory.providers[0] = {
    ...validProvider,
    evidence_max_age_ms: 200_000,
    observed_at_unix_ms: 900_000,
    update_checked_at_unix_ms: 950_000
  };
  assert.equal(
    vm.runInContext("validSecurityProviderInventory(inventory, 1000000, devices)", context),
    false,
    "an update check must not post-date its source observation beyond clock skew"
  );

  context.inventory.providers[0] = {
    ...validProvider,
    update_posture: "current",
    update_checked_at_unix_ms: 1
  };
  assert.equal(
    vm.runInContext("validSecurityProviderInventory(inventory, 1000000, devices)", context),
    false
  );

  context.inventory.providers[0] = {
    ...validProvider,
    evidence_freshness: "stale",
    observed_at_unix_ms: 1,
    update_posture: "unverified",
    update_checked_at_unix_ms: null
  };
  assert.equal(
    vm.runInContext("validSecurityProviderInventory(inventory, 1000000, devices)", context),
    true
  );
  vm.runInContext("renderSecurityProviderInventory(inventory)", context);
  assert.match(collectText(getElement("security-provider-inventory")), /stale/);
  assert.match(collectText(getElement("security-provider-inventory")), /not treated as current/);
});



test("model catalogue task filter is explicit and uses only declared catalogue metadata", async () => {
  const source = await readAppSource();
  const elements = new Map();
  const getElement = (id) => {
    if (!elements.has(id)) elements.set(id, new FakeElement());
    return elements.get(id);
  };
  const context = vm.createContext({
    document: {
      getElementById: getElement,
      createElement: () => new FakeElement(),
      addEventListener: () => {},
      hidden: false
    },
    window: { setTimeout: () => 1, clearTimeout: () => {}, addEventListener: () => {} },
    fetch: async () => ({ ok: false, status: 404 }),
    AbortController,
    console
  });
  vm.runInContext(source, context);
  const catalogue = {
    schema_version: 1,
    models: [
      { id: "small-chat", display_name: "Small Chat", publisher: "Example", purpose: "Chat", tasks: ["chat", "summarization"], limitations: ["Limited reasoning"], planning_ram_gib: { minimum: 4, recommended: 8 }, license: "Example licence" },
      { id: "code-model", display_name: "Code Model", publisher: "Example", purpose: "Coding", tasks: ["coding_assistance"], limitations: ["Slower"], planning_ram_gib: { minimum: 8, recommended: 16 }, license: "Example licence" }
    ],
    specialist_tools: []
  };
  context.catalogue = catalogue;
  vm.runInContext("renderModelCatalogue(catalogue)", context);
  const filter = getElement("model-catalogue-task-filter");
  assert.equal(filter.children.length, 4, "all-task option plus the three distinct declared tasks are shown");
  assert.deepEqual(
    filter.children.map((option) => option.value),
    ["all", "chat", "coding_assistance", "summarization"]
  );
  assert.equal(getElement("model-catalogue").children.length, 3, "two model cards plus the summary are shown initially");

  filter.value = "coding_assistance";
  filter.onchange();
  assert.equal(getElement("model-catalogue").children.length, 2, "one matching model card plus the summary is shown");
  assert.match(collectText(getElement("model-catalogue")), /Code Model/);
  assert.doesNotMatch(collectText(getElement("model-catalogue")), /Small Chat/);
  assert.match(collectText(getElement("model-catalogue")), /not verified runtime capability/);
});


test("device inventory search, state filters and pagination are bounded and accessible", async () => {
  const source = await readAppSource();
  const elements = new Map();
  const getElement = (id) => {
    if (!elements.has(id)) elements.set(id, new FakeElement());
    return elements.get(id);
  };
  const context = vm.createContext({
    document: {
      getElementById: getElement,
      createElement: () => new FakeElement(),
      addEventListener: () => {},
      hidden: false
    },
    window: { setTimeout: () => 1, clearTimeout: () => {}, addEventListener: () => {} },
    fetch: async (url) => url === "./model-catalog.json"
      ? Promise.reject(new Error("test fixture: catalogue unavailable"))
      : ({ ok: false, status: 404 }),
    AbortController,
    console
  });
  vm.runInContext(source, context);
  await new Promise((resolve) => setImmediate(resolve));
  context.devices = Array.from({ length: 53 }, (_, index) => ({
    device_id: "device-" + String(index + 1).padStart(2, "0"),
    display_name: index === 50 ? "GPU workstation" : "Office workstation " + (index + 1),
    platform: index % 2 ? "Windows" : "Linux",
    trust_state: index === 51 ? "revoked" : "enrolled",
    availability: index === 52 ? "paused" : "schedulable",
    remaining_cpu_millis: 2000,
    remaining_memory_mb: 4096,
    last_seen_unix_ms: 1_000_000
  }));
  vm.runInContext("renderDevices(devices)", context);
  assert.equal(getElement("devices").children.length, 50, "only the first 50 inventory rows should be rendered");
  assert.equal(getElement("device-page-status").textContent, "Page 1 of 2");
  assert.equal(getElement("device-page-previous").disabled, true);
  assert.equal(getElement("device-page-next").disabled, false);
  assert.match(getElement("device-filter-summary").textContent, /Showing 1–50 of 53 matching devices/);

  getElement("device-page-next").listeners.click();
  assert.equal(getElement("devices").children.length, 3, "the second page contains only the remaining records");
  assert.equal(getElement("device-page-status").textContent, "Page 2 of 2");
  assert.equal(getElement("device-page-next").disabled, true);
  getElement("device-page-previous").listeners.click();
  assert.equal(getElement("device-page-status").textContent, "Page 1 of 2");

  getElement("device-search").value = "GPU";
  getElement("device-search").listeners.input();
  assert.equal(getElement("devices").children.length, 1);
  assert.match(collectText(getElement("devices")), /GPU workstation/);
  assert.match(getElement("device-filter-summary").textContent, /1 matching devices/);

  getElement("device-search").value = "device-52";
  getElement("device-search").listeners.input();
  getElement("device-trust-filter").value = "revoked";
  getElement("device-trust-filter").listeners.change();
  getElement("device-availability-filter").value = "schedulable";
  getElement("device-availability-filter").listeners.change();
  assert.equal(getElement("devices").children.length, 1, "search by device ID and combined filters must match the same record");
  assert.match(collectText(getElement("devices")), /Office workstation 52/);

  getElement("device-availability-filter").value = "paused";
  getElement("device-availability-filter").listeners.change();
  assert.equal(getElement("devices").children.length, 1);
  assert.match(collectText(getElement("devices")), /No devices match the current filters/);
  assert.match(getElement("device-filter-summary").textContent, /No devices match/);

  getElement("device-filter-reset").listeners.click();
  assert.equal(getElement("device-search").value, "");
  assert.equal(getElement("device-trust-filter").value, "all");
  assert.equal(getElement("device-availability-filter").value, "all");
  assert.equal(getElement("devices").children.length, 50);
  assert.equal(getElement("device-page-status").textContent, "Page 1 of 2");

  getElement("device-trust-filter").value = "revoked";
  getElement("device-trust-filter").listeners.change();
  vm.runInContext("renderDevices(devices)", context);
  assert.equal(getElement("device-trust-filter").value, "all", "a new snapshot must clear stale filters");
  assert.equal(getElement("device-search").value, "");
  assert.equal(getElement("devices").children.length, 50);
});

test("operator console styles preserve keyboard focus and responsive inventory navigation", async () => {
  const css = await readFile(new URL("../styles.css", import.meta.url), "utf8");
  const html = await readFile(new URL("../index.html", import.meta.url), "utf8");
  assert.match(css, /:where\(a,button,input,select,textarea,summary,\[tabindex\]\):focus-visible/);
  assert.match(html, /class="table-wrap" tabindex="0" role="region" aria-label="Device inventory table"/);
  assert.match(html, /for="device-search"/);
  assert.match(html, /id="device-trust-filter"/);
  assert.match(html, /id="device-availability-filter"/);
  assert.match(html, /id="device-filter-summary"[^>]*aria-live="polite"/);
  assert.match(html, /id="device-page-status"[^>]*aria-live="polite"/);
  assert.match(css, /\.device-filters\s*\{[^}]*display:grid/s);
  assert.match(css, /@media\(max-width:520px\)\s*\{[^}]*\.device-filters\s*\{[^}]*grid-template-columns:1fr/s);
  assert.match(html, /class="table-wrap" tabindex="0" role="region" aria-label="Security provider inventory table"/);
  assert.match(html, /class="table-wrap" tabindex="0" role="region" aria-label="Installed model and runtime inventory table"/);
  assert.match(css, /\.table-wrap\s*\{[^}]*max-height:26rem[^}]*overflow-x:auto[^}]*overflow-y:auto/s);
  assert.match(css, /\.table-wrap:focus-visible/);
  assert.match(css, /table thead th\s*\{[^}]*position:sticky/s);
  const narrowLayout = css.slice(css.lastIndexOf("@media(max-width:700px){"));
  assert.match(narrowLayout, /\.topbar\s*\{[^}]*flex-wrap:wrap/s);
  assert.match(narrowLayout, /\.section-title\s*\{[^}]*flex-direction:column/s);
  assert.match(css, /@media\(prefers-reduced-motion:reduce\)/);
});

test("untrusted operator and model-catalogue text is rendered as text, never parsed as HTML", async () => {
  const source = await readAppSource();
  assert.doesNotMatch(
    source,
    /\.innerHTML\s*=|insertAdjacentHTML\s*\(/u,
    "untrusted API/catalogue values must not enter an HTML parsing sink"
  );

  const elements = new Map();
  const getElement = (id) => {
    if (!elements.has(id)) elements.set(id, new FakeElement());
    return elements.get(id);
  };
  const context = vm.createContext({
    document: {
      getElementById: getElement,
      createElement: () => new FakeElement(),
      addEventListener: () => {},
      hidden: false
    },
    window: { setTimeout: () => 1, clearTimeout: () => {}, addEventListener: () => {} },
    fetch: async () => ({ ok: false, status: 404 }),
    AbortController,
    console
  });
  vm.runInContext(source, context);

  const hostile = '<img src=x onerror="alert(1)">';
  context.catalogue = {
    schema_version: 1,
    models: [{
      id: "model-safe-id",
      display_name: hostile,
      publisher: hostile,
      purpose: hostile,
      tasks: ["chat"],
      limitations: [hostile],
      planning_ram_gib: { minimum: 4, recommended: 8 },
      license: hostile
    }],
    specialist_tools: []
  };
  vm.runInContext("renderModelCatalogue(catalogue)", context);
  const catalogueText = collectText(getElement("model-catalogue"));
  assert.ok(catalogueText.includes(hostile), "catalogue text should remain visible literally");
  assert.equal(
    getElement("model-catalogue").children.some((node) => node.tagName === "IMG"),
    false,
    "catalogue values must not create executable DOM elements"
  );

  context.devices = [{
    device_id: "device-1",
    display_name: hostile,
    platform: hostile,
    trust_state: hostile,
    availability: "unknown",
    remaining_cpu_millis: null,
    remaining_memory_mb: null,
    last_seen_unix_ms: null
  }];
  vm.runInContext("renderDevices(devices)", context);
  const deviceText = collectText(getElement("devices"));
  assert.ok(deviceText.includes(hostile), "device values should remain visible literally");
  assert.equal(
    getElement("devices").children.some((row) =>
      row.children.some((cell) => cell.tagName === "IMG")
    ),
    false,
    "device values must not create executable DOM elements"
  );
});


test("authentication and server errors never substitute synthetic fleet data", async () => {
  const source = await readAppSource();
  for (const status of [401, 403, 500, 502]) {
    const elements = new Map();
    const getElement = (id) => {
      if (!elements.has(id)) elements.set(id, new FakeElement());
      return elements.get(id);
    };
    const heading = new FakeElement();
    const message = new FakeElement();
    getElement("notice").querySelector = (selector) => selector === "strong" ? heading : message;
    const context = vm.createContext({
      document: {
        getElementById: getElement,
        createElement: () => new FakeElement(),
        addEventListener: () => {},
        hidden: false
      },
      window: { setTimeout: () => 1, clearTimeout: () => {}, addEventListener: () => {} },
      fetch: async (url) => url === "./model-catalog.json"
        ? Promise.reject(new Error("test fixture: catalogue not loaded"))
        : ({ ok: false, status }),
      AbortController,
      console
    });
    vm.runInContext(source, context);
    await new Promise((resolve) => setImmediate(resolve));
    await vm.runInContext("refreshOverview()", context);
    assert.equal(getElement("demo-banner").hidden, true, `HTTP ${status} must not silently enter demo mode`);
    assert.doesNotMatch(collectText(getElement("devices")), /DEMO/);
    assert.doesNotMatch(collectText(getElement("model-inventory")), /DEMO/);
    assert.doesNotMatch(collectText(getElement("workloads")), /DEMO/);
    assert.doesNotMatch(collectText(getElement("approvals")), /DEMO/);
    assert.equal(getElement("demo").disabled, false, "demo mode must remain a separate explicit user action");
    assert.match(message.textContent, status === 401 || status === 403
      ? /authorized Enterprise operator account/
      : new RegExp(`HTTP ${status}`));
  }
});
