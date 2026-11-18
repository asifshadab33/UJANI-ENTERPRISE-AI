/**
 * Parse a fetch response as JSON while enforcing both declared and streamed byte limits.
 * This is shared by the live overview and the local model catalogue.
 */
export async function readBoundedJson(
  response,
  maxBytes = 8 * 1024 * 1024,
  resourceLabel = "JSON response",
) {
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) {
    throw new TypeError("A positive safe-integer response limit is required.");
  }
  if (typeof resourceLabel !== "string" || resourceLabel.length > 80) {
    throw new TypeError("A bounded response label is required.");
  }

  const contentType = response.headers.get("content-type") || "";
  if (!/^application\/(?:[a-z0-9.+-]*\+)?json(?:\s*;|$)/i.test(contentType)) {
    throw new Error("The response did not contain a valid JSON media type.");
  }
  const declaredLengthHeader = response.headers.get("content-length");
  if (declaredLengthHeader !== null) {
    if (!/^(?:0|[1-9][0-9]*)$/.test(declaredLengthHeader)) {
      throw new Error(`The ${resourceLabel} has an invalid Content-Length.`);
    }
    const declaredLength = Number(declaredLengthHeader);
    if (!Number.isSafeInteger(declaredLength) || declaredLength > maxBytes) {
      throw new Error(`The ${resourceLabel} exceeds its ${Math.ceil(maxBytes / 1024)} KiB response limit or has an invalid Content-Length.`);
    }
  }
  if (!response.body || typeof response.body.getReader !== "function") {
    throw new Error("This browser cannot safely stream a bounded JSON response.");
  }

  const reader = response.body.getReader();
  const chunks = [];
  let totalBytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!(value instanceof Uint8Array)) {
        await reader.cancel().catch(() => {});
        throw new Error("The response stream did not provide byte chunks.");
      }
      if (value.byteLength > maxBytes - totalBytes) {
        await reader.cancel().catch(() => {});
        throw new Error(`The ${resourceLabel} exceeds its ${Math.ceil(maxBytes / 1024)} KiB response limit.`);
      }
      totalBytes += value.byteLength;
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
    throw new Error("The response contained malformed UTF-8 or JSON.");
  }
}
