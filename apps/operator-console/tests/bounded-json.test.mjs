import test from "node:test";
import assert from "node:assert/strict";
import { readBoundedJson } from "../boundedJson.js";

test("parses a bounded JSON response including a vendor JSON media type", async () => {
  const response = new Response(JSON.stringify({ schema_version: 1, devices: [] }), {
    headers: { "content-type": "application/vnd.ujani.overview+json; charset=utf-8" },
  });
  assert.deepEqual(await readBoundedJson(response, 1024, "overview"), {
    schema_version: 1,
    devices: [],
  });
});

test("rejects a declared content length above the configured limit", async () => {
  const response = new Response("{}", {
    headers: { "content-type": "application/json", "content-length": "4096" },
  });
  await assert.rejects(readBoundedJson(response, 32, "catalogue"), /response limit/);
});

test("cancels a streamed response as soon as observed bytes exceed the limit", async () => {
  let cancelled = false;
  const body = new ReadableStream({
    start(controller) {
      controller.enqueue(new TextEncoder().encode('{"items":"'));
      controller.enqueue(new Uint8Array(128).fill(97));
    },
    cancel() {
      cancelled = true;
    },
  });
  const response = new Response(body, {
    headers: { "content-type": "application/json" },
  });
  await assert.rejects(readBoundedJson(response, 32, "catalogue"), /response limit/);
  assert.equal(cancelled, true);
});

test("rejects non-JSON media types before reading the body", async () => {
  const response = new Response("{}", {
    headers: { "content-type": "text/plain" },
  });
  await assert.rejects(readBoundedJson(response, 32), /JSON media type/);
});

test("rejects malformed UTF-8 and malformed JSON", async () => {
  const invalidUtf8 = new Response(new Uint8Array([0xff]), {
    headers: { "content-type": "application/json" },
  });
  await assert.rejects(readBoundedJson(invalidUtf8, 32), /malformed UTF-8 or JSON/);

  const invalidJson = new Response("{", {
    headers: { "content-type": "application/json" },
  });
  await assert.rejects(readBoundedJson(invalidJson, 32), /malformed UTF-8 or JSON/);
});

test("rejects invalid response limits and malformed content lengths", async () => {
  const response = new Response("{}", {
    headers: { "content-type": "application/json", "content-length": "" },
  });
  await assert.rejects(readBoundedJson(response, 0), /positive safe-integer/);
  await assert.rejects(readBoundedJson(response, 32), /invalid Content-Length/);
});
