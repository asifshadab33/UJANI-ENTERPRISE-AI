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
    assert "No sample data is shown" in js and "No live device inventory" in html, "Missing no-demo-data fallback."
    assert "frame-ancestors" not in html, "Frame denial must be delivered as a server response header, not a meta policy."
    assert "schedulable_devices" in js and "remaining_memory_mb" in js, "Capacity fields missing."
    assert "overflow" in css or "overflow-x" in css, "Responsive table overflow handling missing."
    print("Operator console static security/contract checks passed.")

if __name__ == "__main__":
    main()
