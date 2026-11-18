import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";
import { readBoundedJson } from "../boundedJson.js";

async function readAppSource() {
  const source = await readAppSource();
  return source.replace(/^import \\{ readBoundedJson \\} from \"\\.\\/boundedJson\\.js\";\\s*/u, "");
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
  const fetchMock = (url) => {
    requestedUrls.push(url);
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
