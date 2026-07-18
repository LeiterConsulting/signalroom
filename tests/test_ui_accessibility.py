import re
from pathlib import Path

STATIC_ROOT = Path(__file__).parents[1] / "src" / "splunk_security_agent" / "static"
INDEX_HTML = (STATIC_ROOT / "index.html").read_text(encoding="utf-8")
STYLES_CSS = (STATIC_ROOT / "styles.css").read_text(encoding="utf-8")
APP_JS = (STATIC_ROOT / "app.js").read_text(encoding="utf-8")


def test_switches_use_the_shared_accessible_control() -> None:
    switch_labels = len(re.findall(r'class="[^"]*\bswitch-line\b', INDEX_HTML))
    switch_controls = len(re.findall(r'class="switch-control"', INDEX_HTML))

    assert switch_labels > 0
    assert switch_controls == switch_labels
    assert ".switch-line input{display:none}" not in STYLES_CSS
    assert ".switch-line>.switch-control" in STYLES_CSS
    assert ".switch-line>input:focus-visible+.switch-control" in STYLES_CSS


def test_ui_uses_readable_system_type_scale() -> None:
    pixel_sizes = [
        int(value)
        for value in re.findall(r"(?:font-size:|font:[^;{}]*?)(\d+)px", STYLES_CSS)
    ]

    assert pixel_sizes
    assert min(pixel_sizes) >= 12
    assert "DM Mono" not in STYLES_CSS
    assert '"Segoe UI Variable Text"' in STYLES_CSS
    assert "--font-mono:" in STYLES_CSS


def test_discovery_presents_securebert_labels_as_validated_candidates() -> None:
    assert "Validated SecureBERT context" in APP_JS
    assert "Entity labels are candidates, not findings." in APP_JS
    assert "suppressed before synthesis and RAG" in APP_JS
    assert "<h4>SecureBERT enrichment</h4>" not in APP_JS


def test_delivery_exposes_adapter_semantics_before_approval() -> None:
    assert 'id="deliveryKind"' in INDEX_HTML
    assert 'value="slack-incoming-webhook"' in INDEX_HTML
    assert 'id="deliveryAdapterHelp"' in INDEX_HTML
    assert 'id="deliveryWarnings"' in INDEX_HTML
    assert "Configure generic webhook policy" not in INDEX_HTML
    assert "Slack receives plain-text notification blocks only over verified TLS." in APP_JS
    assert "no SPL execution or validation approval" in APP_JS
