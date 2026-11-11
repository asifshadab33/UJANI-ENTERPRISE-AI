from html.parser import HTMLParser
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "apps" / "operator-console"

class ConsoleParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.inline_scripts = 0
        self.inline_styles = 0
        self.inline_handlers = []
        self.script_sources = []

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "script":
            if not values.get("src"):
                self.inline_scripts += 1
            else:
                self.script_sources.append(values["src"])
        if tag == "style":
            self.inline_styles += 1
        for name in values:
            if name.lower().startswith("on"):
                self.inline_handlers.append((tag, name))

def main():
    html = (APP / "index.html").read_text(encoding="utf-8")
    js = (APP / "app.js").read_text(encoding="utf-8")
    css = (APP / "styles.css").read_text(encoding="utf-8")
    parser = ConsoleParser()
    parser.feed(html)
    assert parser.inline_scripts == 0, "Console must not use inline scripts."
    assert parser.inline_styles == 0, "Console must not use inline style blocks."
    assert not parser.inline_handlers, f"Inline event handlers found: {parser.inline_handlers}"
    assert parser.script_sources == ["./app.js"], "Only the local application module may be loaded."
    assert "default-src 'self'" in html and "connect-src 'self'" in html, "Same-origin CSP is required."
    assert 'const API_PATH = "/api/v1/operator/overview";' in js, "Expected fixed same-origin API path."
    assert 'credentials: "same-origin"' in js and 'cache: "no-store"' in js, "Session and cache controls are required."
    assert 'method: "GET"' in js and 'redirect: "error"' in js, "The initial console must remain read-only."
    assert "innerHTML" not in js and "eval(" not in js and "new Function" not in js, "Unsafe DOM/code execution primitive found."
    assert "replaceChildren" in js and "textContent" in js, "Render API values using safe DOM text APIs."
    assert "MAX_OVERVIEW_RESPONSE_BYTES = 8 * 1024 * 1024" in js, "Overview response must have a hard byte ceiling."
    assert "new AbortController()" in js and "controller.abort(), 10_000" in js and "signal: controller.signal" in js, "Overview requests must have a finite timeout."
    assert "window.clearTimeout(requestTimeout)" in js, "Overview request timeout must always be cleared."
    assert "await readBoundedJson(response)" in js, "Overview JSON must be parsed only after bounded streaming."
    assert "content-length" in js and "reader.read()" in js and "reader.cancel()" in js, "Response stream must enforce declared and observed byte limits."
    assert "data.devices.length <= 10000" in js and "data.workloads.length <= 1000" in js and "data.approvals.length <= 1000" in js, "Overview collections must match backend bounds."
    assert "counts.schedulable_devices <= counts.online_fresh_devices" in js, "Fleet counts must be internally consistent."
    assert "MAX_OVERVIEW_SNAPSHOT_AGE_MS = 5 * 60 * 1000" in js, "Fleet snapshots must have a bounded freshness window."
    assert "MAX_OVERVIEW_CLOCK_SKEW_MS = 60 * 1000" in js and "snapshotIsFresh(data.generated_at_unix_ms)" in js, "Future or stale snapshots must not appear live."
    assert "No sample data is shown" in js and "No live device inventory" in html, "Missing no-demo-data fallback."
    assert "frame-ancestors" not in html, "Frame denial must be delivered as a server response header, not a meta policy."
    assert "schedulable_devices" in js and "remaining_memory_mb" in js, "Capacity fields missing."
    assert 'id="model-inventory"' in html and 'id="model-count"' in html, "Model inventory table and count must be present."
    assert "function validModelInventory" in js and "function validEvidence" in js, "Model inventory evidence must be structurally validated."
    assert "inventory.runtimes.length <= 16" in js and "inventory.models.length <= 512" in js, "Runtime/model inventory bounds are missing."
    assert "snapshotIsFresh(inventory.generated_at_unix_ms)" in js, "Model inventory snapshots must be fresh."
    assert "rows.length < 5120" in js and "totalModels > rows.length" in js, "Model row allocation must remain bounded."
    assert "cell.colSpan = 9" in js, "Model inventory empty state must span all nine columns."
    assert "entry.inventory" in js and "inventory.schema_version === 1" in js, "Console must consume the shared v1 inventory wrapper."
    assert "device_id: entry.device_id" in js, "Console must preserve the outer tenant-scoped device identifier."
    assert "inventory.privacy" in js, "Console must reject inventory privacy flags that disclose user data."
    assert "validEvidence(model.evidence, inventory.generated_at_unix_ms)" in js and "snapshotIsFresh(evidenceAt)" in js, "Model evidence must expose confidence and snapshot-relative freshness."
    assert "containsLocalPath(model.display_name)" in js and "containsLocalPath(model.model_ref)" in js, "Local paths must not be rendered as model labels."
    assert "model.estimated_min_memory_mb <= MAX_MODEL_MEMORY_ESTIMATE_MB" in js, "Model memory estimates must match the API bounds."
    assert "model_inventory_status" in js and "model_inventory_total_models" in js, "Partial inventory responses must be explicitly summarized."
    assert "inventory.hardware.memory_available_mb" in js and "estimate fits" in js and "insufficient" in js, "Model RAM fit must be conservative and explicit."
    assert "<th>RAM fit</th>" in html, "Model RAM fit column is missing."
    assert "renderModelInventory(data.model_inventory)" in js, "Authenticated model inventory must be rendered."
    assert "prompts, model contents and local file paths are never displayed" in html.lower(), "Model inventory privacy boundary must be visible."
    assert "overflow" in css or "overflow-x" in css, "Responsive table overflow handling missing."
    control_plane = (ROOT / "crates" / "ujani-enterprise-policy" / "src" / "operator_control_plane.rs").read_text(encoding="utf-8")
    for required in (
        "pub model_inventory: Vec<OperatorModelInventoryView>",
        "fn json_model_inventory(",
        "fn valid_inventory_evidence(",
        "inventory.schema_version != 1",
        "inventory.platform.os",
        "inventory.hardware.accelerators.len() > 32",
        "inventory.privacy.as_ref()",
        "inventory.generated_at_unix_ms",
        "inventory.runtimes.len() > 16",
        "inventory.models.len() > 512",
        "total_model_rows.is_none_or",
        "MAX_TOTAL_MODEL_ROWS: usize = 100_000",
        "MAX_OVERVIEW_RESPONSE_BYTES: usize = 8 * 1024 * 1024",
        "contains_local_path(&model.display_name)",
        "inventory_devices.insert(inventory.device_id.as_str())",
    ):
        if required not in control_plane:
            raise SystemExit(f"operator API model inventory contract is missing: {required}")
    serializer = control_plane.split("impl OperatorOverview", 1)[1].split("fn json_string", 1)[0]
    assert '\\"tenant_id\\":{}' in serializer, "Serialized overview must include tenant_id required by the console."
    assert "partial_response_budget" in serializer and "model_inventory_returned_models" in serializer, "Serializer must expose explicit bounded-inventory status and counts."
    assert "MAX_OVERVIEW_RESPONSE_BYTES" in serializer, "Serializer must enforce the console response byte ceiling."
    print("Operator console and model inventory API static security/contract checks passed.")

if __name__ == "__main__":
    main()
