from __future__ import annotations

import argparse
import json
import os
import socket
from datetime import UTC, datetime
from pathlib import Path

import uvicorn


def _port_available(host: str, port: int) -> bool:
    bind_host = "127.0.0.1" if host in {"0.0.0.0", "::"} else host
    family = socket.AF_INET6 if ":" in bind_host else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((bind_host, port))
            return True
        except OSError:
            return False


def resolve_port(host: str, preferred: int, scan: int = 20) -> int:
    for candidate in range(preferred, preferred + scan + 1):
        if _port_available(host, candidate):
            return candidate
    raise RuntimeError(f"No available port found in the range {preferred}-{preferred + scan}.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the SignalRoom local web service")
    parser.add_argument("--host", default=os.getenv("SIGNALROOM_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("SIGNALROOM_PORT", "8003")))
    parser.add_argument("--port-scan", type=int, default=20)
    parser.add_argument("--runtime-file", default=os.getenv("SIGNALROOM_RUNTIME_FILE", ""))
    return parser


def _write_runtime_file(path: str, host: str, port: int) -> None:
    if not path:
        return
    runtime_path = Path(path).resolve()
    runtime_path.parent.mkdir(parents=True, exist_ok=True)
    if host == "0.0.0.0":
        display_host = "127.0.0.1"
    elif host == "::":
        display_host = "[::1]"
    elif ":" in host and not host.startswith("["):
        display_host = f"[{host}]"
    else:
        display_host = host
    runtime_path.write_text(
        json.dumps(
            {
                "pid": os.getpid(),
                "host": host,
                "port": port,
                "url": f"http://{display_host}:{port}",
                "started_at": datetime.now(UTC).isoformat(),
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def run() -> None:
    args = build_parser().parse_args()
    port = resolve_port(args.host, args.port, max(0, args.port_scan))
    if port != args.port:
        print(f"Preferred port {args.port} is busy; using {port}.", flush=True)
    _write_runtime_file(args.runtime_file, args.host, port)
    try:
        uvicorn.run("splunk_security_agent.app:app", host=args.host, port=port, reload=False)
    finally:
        if args.runtime_file:
            runtime_path = Path(args.runtime_file).resolve()
            try:
                current = json.loads(runtime_path.read_text(encoding="utf-8"))
                if current.get("pid") == os.getpid():
                    runtime_path.unlink(missing_ok=True)
            except (OSError, ValueError, json.JSONDecodeError):
                pass


if __name__ == "__main__":
    run()
