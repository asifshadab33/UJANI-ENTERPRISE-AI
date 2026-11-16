import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

class FakeElement {
  constructor() {
    this.textContent = "";
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
  const source = await readFile(
    new URL("../app.js", import.meta.url),
    "utf8"
  );
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
      createElement: () => new FakeElement()
    },
    window: {
      setTimeout: () => 1,
      clearTimeout: () => {}
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
  const source = await readFile(new URL("../app.js", import.meta.url), "utf8");
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
    document: { getElementById: getElement, createElement: () => new FakeElement() },
    window: { setTimeout: () => 1, clearTimeout: () => {} },
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

  monotonicNow += 200_001;
  assert.equal(vm.runInContext("snapshotIsFresh(1_880_000)", context), false);
});
