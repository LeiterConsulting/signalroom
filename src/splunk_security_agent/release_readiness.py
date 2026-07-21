from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

SETTINGS_SECTIONS = (
    ("settingsSplunk", "Splunk MCP"),
    ("settingsConnections", "Connections and tenant scope"),
    ("settingsModels", "Model services"),
    ("settingsRepository", "Detection repository"),
    ("accessControlSection", "Access control"),
    ("recoverySection", "Recovery and retention"),
    ("workloadPolicySection", "Workload protection"),
    ("settingsAgent", "Agent execution"),
    ("settingsRelease", "Release readiness"),
)
MAX_CONTROLS_PER_SETTINGS_SECTION = 32
RECEIPT_NAME = "release_candidate_receipt.json"
SOURCE_SUFFIXES = {
    ".css",
    ".html",
    ".js",
    ".json",
    ".md",
    ".ps1",
    ".py",
    ".sh",
    ".toml",
    ".yaml",
    ".yml",
}
CONTRAST_PAIRS = (
    ("primary text", "#17201b", "#f4f6f2"),
    ("secondary text", "#4f5d55", "#fbfcf9"),
    ("navigation text", "#ffffff", "#14251d"),
    ("action green", "#075f3a", "#ffffff"),
    ("warning text", "#68420b", "#fff8e9"),
    ("error text", "#762d27", "#f9e9e7"),
    ("informational text", "#315f80", "#f7faf8"),
)


def _now() -> str:
    return datetime.now(UTC).isoformat()


class _InterfaceParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[tuple[str, dict[str, str]]] = []
        self.ids: list[str] = []
        self.settings_sections: dict[str, dict[str, Any]] = {}
        self.settings_targets: list[str] = []
        self.unlabelled_controls: list[str] = []
        self.details_count = 0
        self.details_without_summary: list[str] = []
        self._details: list[dict[str, Any]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key: value or "" for key, value in attrs}
        self.stack.append((tag, values))
        if values.get("id"):
            self.ids.append(values["id"])
        target = values.get("data-settings-target")
        if target:
            self.settings_targets.append(target)
        section_id = values.get("data-settings-section")
        if section_id:
            self.settings_sections[section_id] = {
                "title": values.get("data-settings-title", ""),
                "controls": 0,
            }
        if tag == "details":
            self.details_count += 1
            self._details.append(
                {
                    "id": values.get("id") or f"details-{self.details_count}",
                    "summary": False,
                }
            )
        elif tag == "summary" and self._details:
            self._details[-1]["summary"] = True
        if tag not in {"input", "select", "textarea"}:
            return
        if values.get("type") == "hidden":
            return
        current_section = next(
            (
                item_attrs.get("data-settings-section")
                for _item_tag, item_attrs in reversed(self.stack)
                if item_attrs.get("data-settings-section")
            ),
            "",
        )
        if current_section:
            self.settings_sections[current_section]["controls"] += 1
            labelled = (
                any(item_tag == "label" for item_tag, _item_attrs in self.stack[:-1])
                or bool(values.get("aria-label"))
                or bool(values.get("aria-labelledby"))
            )
            if not labelled:
                self.unlabelled_controls.append(values.get("id") or f"{tag}-without-id")

    def handle_endtag(self, tag: str) -> None:
        if tag == "details" and self._details:
            item = self._details.pop()
            if not item["summary"]:
                self.details_without_summary.append(str(item["id"]))
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index][0] == tag:
                del self.stack[index:]
                break


def _hex_rgb(value: str) -> tuple[float, float, float]:
    clean = value.lstrip("#")
    if len(clean) == 3:
        clean = "".join(character * 2 for character in clean)
    return tuple(int(clean[index : index + 2], 16) / 255 for index in (0, 2, 4))  # type: ignore[return-value]


def _luminance(value: str) -> float:
    channels = [
        channel / 12.92
        if channel <= 0.04045
        else ((channel + 0.055) / 1.055) ** 2.4
        for channel in _hex_rgb(value)
    ]
    return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2]


def contrast_ratio(foreground: str, background: str) -> float:
    light, dark = sorted((_luminance(foreground), _luminance(background)), reverse=True)
    return round((light + 0.05) / (dark + 0.05), 2)


def source_digest(root: Path) -> str:
    root = root.resolve()
    files: list[Path] = []
    for relative in ("docs", "src", "tests"):
        directory = root / relative
        if directory.exists():
            files.extend(
                path
                for path in directory.rglob("*")
                if path.is_file() and path.suffix.lower() in SOURCE_SUFFIXES
            )
    for name in (
        "README.md",
        "THIRD_PARTY_NOTICES.md",
        "pyproject.toml",
        "compose.yaml",
        "Dockerfile",
        "install.ps1",
        "install.sh",
    ):
        path = root / name
        if path.is_file():
            files.append(path)
    hasher = hashlib.sha256()
    for path in sorted(set(files), key=lambda value: value.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        hasher.update(relative.encode())
        hasher.update(b"\0")
        hasher.update(path.read_bytes())
        hasher.update(b"\0")
    return hasher.hexdigest()


def _check(identifier: str, title: str, passed: bool, summary: str, evidence: Any) -> dict[str, Any]:
    return {
        "id": identifier,
        "title": title,
        "status": "pass" if passed else "block",
        "summary": summary,
        "evidence": evidence,
    }


class ReleaseReadinessService:
    """Source-bound release checks for interface quality and verification receipts."""

    def __init__(self, root: Path, static_root: Path, data_root: Path, version: str):
        self.root = root.resolve()
        self.static_root = static_root.resolve()
        self.data_root = data_root.resolve()
        self.version = version
        self.receipt_path = self.data_root / RECEIPT_NAME

    def static_checks(self) -> list[dict[str, Any]]:
        html = (self.static_root / "index.html").read_text(encoding="utf-8")
        css = (self.static_root / "styles.css").read_text(encoding="utf-8")
        javascript = (self.static_root / "app.js").read_text(encoding="utf-8")
        parser = _InterfaceParser()
        parser.feed(html)
        expected = [identifier for identifier, _title in SETTINGS_SECTIONS]
        observed = list(parser.settings_sections)
        navigation_ok = observed == expected and parser.settings_targets == expected
        duplicate_ids = sorted({value for value in parser.ids if parser.ids.count(value) > 1})
        density = {
            identifier: int(parser.settings_sections.get(identifier, {}).get("controls") or 0)
            for identifier in expected
        }
        dense = {key: value for key, value in density.items() if value > MAX_CONTROLS_PER_SETTINGS_SECTION}
        font_sizes = [
            int(value)
            for value in re.findall(r"(?:font-size:|font:[^;{}]*?)(\d+)px", css)
        ]
        contrast = [
            {
                "surface": label,
                "foreground": foreground,
                "background": background,
                "ratio": contrast_ratio(foreground, background),
            }
            for label, foreground, background in CONTRAST_PAIRS
        ]
        contrast_failures = [item for item in contrast if item["ratio"] < 4.5]
        forbidden_patterns = {
            "unfinished marker": r"\b(?:TODO|FIXME|HACK)\b",
            "debug surface": r"\bdebug(?:ger)?\b",
            "development-only copy": r"\bdev(?:elopment)?[- ]only\b",
            "placeholder implementation": r"\b(?:fake data|not implemented|coming soon)\b",
            "vague instruction": r"\bclick here\b",
        }
        language_hits = {
            label: sorted(
                set(
                    match.group(0)
                    for match in re.finditer(
                        pattern, html + "\n" + javascript, re.IGNORECASE
                    )
                )
            )
            for label, pattern in forbidden_patterns.items()
        }
        language_hits = {key: value for key, value in language_hits.items() if value}
        functions = re.findall(
            r"(?m)^(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(", javascript
        )
        functions.extend(
            re.findall(
                r"(?m)^const\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:async\s*)?(?:\([^\n]*\)|[A-Za-z_$][A-Za-z0-9_$]*)\s*=>",
                javascript,
            )
        )
        interface_orphans = sorted(
            name
            for name in functions
            if len(re.findall(rf"(?<![A-Za-z0-9_$]){re.escape(name)}(?![A-Za-z0-9_$])", javascript)) < 2
        )
        python_files = sorted((self.root / "src" / "splunk_security_agent").rglob("*.py"))
        python_text = "\n".join(path.read_text(encoding="utf-8") for path in python_files)
        pyproject = self.root / "pyproject.toml"
        if pyproject.is_file():
            python_text += "\n" + pyproject.read_text(encoding="utf-8")
        backend_orphans = []
        backend_functions = 0
        for path in python_files:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in tree.body:
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                if node.decorator_list or node.name.startswith("__"):
                    continue
                backend_functions += 1
                references = len(
                    re.findall(
                        rf"(?<![A-Za-z0-9_]){re.escape(node.name)}(?![A-Za-z0-9_])",
                        python_text,
                    )
                )
                if references < 2:
                    backend_orphans.append(
                        f"{path.relative_to(self.root).as_posix()}:{node.lineno}:{node.name}"
                    )
        orphan_candidates = [
            *(f"static/app.js:{name}" for name in interface_orphans),
            *backend_orphans,
        ]
        return [
            _check(
                "settings-navigation",
                "Settings navigation and orientation",
                navigation_ok,
                "Every operational section has one ordered navigation target and scroll-aware identity."
                if navigation_ok
                else "Settings sections and navigation targets are missing, duplicated, or out of order.",
                {"expected": expected, "sections": observed, "targets": parser.settings_targets},
            ),
            _check(
                "settings-density",
                "Settings page density",
                not dense,
                f"No section exceeds {MAX_CONTROLS_PER_SETTINGS_SECTION} visible form controls."
                if not dense
                else "One or more settings sections must be split or progressively disclosed.",
                {
                    "limit": MAX_CONTROLS_PER_SETTINGS_SECTION,
                    "controls_by_section": density,
                    "over_limit": dense,
                },
            ),
            _check(
                "control-labels",
                "Control names and help association",
                not parser.unlabelled_controls and not duplicate_ids,
                "Every settings control has an accessible name and every document ID is unique."
                if not parser.unlabelled_controls and not duplicate_ids
                else "Unlabelled controls or duplicate IDs make the interface ambiguous.",
                {"unlabelled_controls": parser.unlabelled_controls, "duplicate_ids": duplicate_ids},
            ),
            _check(
                "disclosure-cues",
                "Collapsible-section affordances",
                not parser.details_without_summary
                and "details>summary::before" in css
                and "details[open]>summary::before" in css
                and "details>summary:focus-visible" in css,
                "Every disclosure has a summary plus visible open/closed and keyboard-focus indicators.",
                {"details": parser.details_count, "missing_summary": parser.details_without_summary},
            ),
            _check(
                "legibility",
                "Type scale and responsive legibility",
                bool(font_sizes)
                and min(font_sizes) >= 12
                and ':root{' in css
                and 'font-size:16px' in css
                and '"Segoe UI Variable Text"' in css
                and "@media(max-width:650px)" in css,
                (
                    "The shipped interface uses a 16 px root, no text below 12 px, "
                    "a readable system stack, and a small-screen layout."
                ),
                {"minimum_font_px": min(font_sizes) if font_sizes else None, "root_font_px": 16},
            ),
            _check(
                "contrast",
                "Critical text contrast",
                not contrast_failures,
                "Every critical semantic foreground/background pair meets WCAG AA 4.5:1."
                if not contrast_failures
                else "One or more critical semantic color pairs fail WCAG AA.",
                {"pairs": contrast, "failures": contrast_failures},
            ),
            _check(
                "production-language",
                "Production-ready interface language",
                not language_hits,
                (
                    "Shipped interface copy contains no unfinished markers, debug surfaces, "
                    "or vague click instructions."
                )
                if not language_hits
                else "Developer-facing or unfinished language remains in shipped interface assets.",
                {"hits": language_hits},
            ),
            _check(
                "function-ownership",
                "User-interface function ownership",
                not orphan_candidates,
                (
                    f"All {len(functions)} interface and {backend_functions} source-level backend functions "
                    "have an explicit call, registration, or entry point."
                )
                if not orphan_candidates
                else "Unreferenced interface functions require removal or assignment to a follow-up slice.",
                {
                    "declared_interface_functions": len(functions),
                    "declared_backend_functions": backend_functions,
                    "backend_modules_scanned": len(python_files),
                    "orphan_candidates": orphan_candidates,
                },
            ),
        ]

    def _receipt(self, digest: str) -> tuple[dict[str, Any] | None, dict[str, Any]]:
        try:
            receipt = json.loads(self.receipt_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError):
            receipt = None
        current = bool(
            receipt
            and receipt.get("status") == "pass"
            and receipt.get("source_sha256") == digest
            and receipt.get("ui_review", {}).get("note")
            and receipt.get("ui_review", {}).get("reviewer")
        )
        check = _check(
            "verification-receipt",
            "Source-bound acceptance receipt",
            current,
            "The full lint, JavaScript syntax, test, and reviewed-viewport receipt matches this exact source."
            if current
            else "Run the full release check with a named UI review after the final source change.",
            {
                "receipt_present": bool(receipt),
                "receipt_source_sha256": (receipt or {}).get("source_sha256", ""),
                "current_source_sha256": digest,
                "ui_review": (receipt or {}).get("ui_review", {}),
            },
        )
        return receipt, check

    def overview(self) -> dict[str, Any]:
        digest = source_digest(self.root)
        checks = self.static_checks()
        receipt, receipt_check = self._receipt(digest)
        checks.append(receipt_check)
        blockers = [item for item in checks if item["status"] == "block"]
        orphan_candidates = next(
            (
                item["evidence"]["orphan_candidates"]
                for item in checks
                if item["id"] == "function-ownership"
            ),
            [],
        )
        follow_ups = []
        if orphan_candidates:
            follow_ups.append(
                {
                    "id": "function-ownership",
                    "title": "Corral unowned interface functions",
                    "items": orphan_candidates,
                }
            )
        static_blockers = [item["id"] for item in blockers if item["id"] != "verification-receipt"]
        if static_blockers:
            follow_ups.append(
                {
                    "id": "interface-remediation",
                    "title": "Resolve measurable interface blockers",
                    "items": static_blockers,
                }
            )
        if not receipt_check["status"] == "pass":
            follow_ups.append(
                {
                    "id": "acceptance-verification",
                    "title": "Run source-bound release acceptance",
                    "items": ["ruff", "node --check", "pytest", "named viewport review"],
                }
            )
        return {
            "version": self.version,
            "generated_at": _now(),
            "source_sha256": digest,
            "decision": "ready" if not blockers else "blocked",
            "counts": {
                "passed": sum(item["status"] == "pass" for item in checks),
                "blocked": len(blockers),
                "total": len(checks),
            },
            "checks": checks,
            "receipt": receipt,
            "follow_up_slices": follow_ups,
            "command": (
                "signalroom-release-check --full --reviewer \"<name>\" "
                "--ui-review \"<viewports and workflows reviewed>\""
            ),
        }


def _run_command(command: list[str], root: Path) -> dict[str, Any]:
    started_at = _now()
    completed = subprocess.run(
        command,
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    output = (completed.stdout + completed.stderr).strip()
    return {
        "command": command,
        "status": "pass" if completed.returncode == 0 else "fail",
        "returncode": completed.returncode,
        "started_at": started_at,
        "completed_at": _now(),
        "output_tail": output[-6000:],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Evaluate SignalRoom release-candidate source and interface gates."
    )
    parser.add_argument("--root", default=str(Path.cwd()))
    parser.add_argument("--data-dir", default="")
    parser.add_argument("--full", action="store_true", help="Run lint, JavaScript syntax, and all tests.")
    parser.add_argument("--reviewer", default="")
    parser.add_argument("--ui-review", default="")
    parser.add_argument("--json", action="store_true")
    return parser


def run() -> None:
    args = build_parser().parse_args()
    root = Path(args.root).resolve()
    data = Path(args.data_dir).resolve() if args.data_dir else root / "data"
    static = root / "src" / "splunk_security_agent" / "static"
    service = ReleaseReadinessService(root, static, data, "0.1.0")
    static_checks = service.static_checks()
    static_blockers = [item for item in static_checks if item["status"] == "block"]
    payload: dict[str, Any] = {
        "status": "pass" if not static_blockers else "fail",
        "source_sha256": source_digest(root),
        "checks": static_checks,
        "commands": [],
    }
    if args.full:
        if len(args.reviewer.strip()) < 2 or len(args.ui_review.strip()) < 12:
            raise SystemExit("--full requires --reviewer and a specific --ui-review note.")
        node = shutil.which("node")
        commands = [
            [sys.executable, "-m", "ruff", "check", "src", "tests"],
            [node or "node", "--check", "src/splunk_security_agent/static/app.js"],
            [sys.executable, "-m", "pytest", "-q"],
        ]
        if not node:
            payload["commands"].append(
                {
                    "command": ["node", "--check", "src/splunk_security_agent/static/app.js"],
                    "status": "fail",
                    "returncode": 127,
                    "output_tail": "Node.js was not found on PATH.",
                }
            )
        else:
            payload["commands"] = [_run_command(command, root) for command in commands]
        payload["status"] = (
            "pass"
            if not static_blockers
            and payload["commands"]
            and all(item["status"] == "pass" for item in payload["commands"])
            else "fail"
        )
        payload["created_at"] = _now()
        payload["ui_review"] = {
            "reviewer": args.reviewer.strip()[:120],
            "note": args.ui_review.strip()[:2000],
        }
        data.mkdir(parents=True, exist_ok=True)
        (data / RECEIPT_NAME).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(f"SignalRoom release check: {payload['status'].upper()}")
        for item in static_checks:
            print(f"[{item['status'].upper():5}] {item['title']}: {item['summary']}")
        for item in payload["commands"]:
            print(f"[{item['status'].upper():5}] {' '.join(item['command'])}")
        if args.full:
            print(f"Receipt: {data / RECEIPT_NAME}")
    raise SystemExit(0 if payload["status"] == "pass" else 1)


if __name__ == "__main__":
    run()
