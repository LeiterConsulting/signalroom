from __future__ import annotations

import argparse
import getpass
import json
import os
from collections.abc import Sequence
from pathlib import Path

from .service import RecoveryPackageError, RecoveryPackageService


def _default_data_dir() -> Path:
    root = Path(os.getenv("SIGNALROOM_ROOT", Path.cwd())).resolve()
    return Path(os.getenv("SIGNALROOM_DATA_DIR", root / "data")).resolve()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Host-only SignalRoom control-plane recovery. Inspect packages without mutation or "
            "stage a validated restore for the next SignalRoom process start."
        )
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=_default_data_dir(),
        help="SignalRoom data directory (defaults to SIGNALROOM_DATA_DIR or ./data)",
    )
    parser.add_argument("--version", default="0.1.0", help=argparse.SUPPRESS)
    subcommands = parser.add_subparsers(dest="command", required=True)
    for command in ("inspect", "restore"):
        action = subcommands.add_parser(command)
        action.add_argument("package", type=Path)
    restore = subcommands.choices["restore"]
    restore.add_argument(
        "--host-authorized",
        action="store_true",
        help="Confirm operating-system authorization to administer this SignalRoom data directory",
    )
    cancel = subcommands.add_parser("cancel")
    cancel.add_argument("--host-authorized", action="store_true")
    subcommands.add_parser("status")
    return parser


def _safe_inspection(value: dict[str, object]) -> dict[str, object]:
    return {
        "inspection_id": value["inspection_id"],
        "package_id": value["package_id"],
        "package_sha256": value["package_sha256"],
        "expires_at": value["expires_at"],
        "manifest": value["manifest"],
        "compatibility": value["compatibility"],
        "validations": value["validations"],
        "confirmation": value["confirmation"],
        "inspection_is_read_only": True,
    }


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    service = RecoveryPackageService(args.data_dir.resolve(), args.version)
    try:
        if args.command == "status":
            overview = service.overview()
            print(
                json.dumps(
                    {
                        "data_dir": str(args.data_dir.resolve()),
                        "pending_restore": overview["pending_restore"],
                        "recent_receipts": overview["recent_receipts"],
                        "rollback_checkpoints": overview["rollbacks"],
                    },
                    indent=2,
                )
            )
            return 0
        if args.command == "cancel":
            if not args.host_authorized:
                raise RecoveryPackageError("Use --host-authorized to cancel a pending restore.")
            print(json.dumps(service.cancel_pending("host-recovery"), indent=2))
            return 0
        package = args.package.resolve().read_bytes()
        password = getpass.getpass("Recovery package password: ")
        inspected = service.inspect(package, password)
        print(json.dumps(_safe_inspection(inspected), indent=2))
        if args.command == "inspect":
            return 0
        if not args.host_authorized:
            raise RecoveryPackageError("Use --host-authorized to stage a control-plane restore.")
        if not inspected["compatibility"]["compatible"]:
            raise RecoveryPackageError("This package is not compatible with this SignalRoom release.")
        confirmation = input(f"Type {inspected['confirmation']} exactly: ")
        staged = service.stage_restore(
            str(inspected["inspection_id"]),
            password,
            confirmation,
            "host-recovery",
        )
        print(json.dumps(staged, indent=2))
        print("Restore staged. Start or restart SignalRoom to revalidate and apply it.")
        return 0
    except (OSError, RecoveryPackageError) as exc:
        print(f"Recovery error: {exc}")
        return 2


def run() -> None:
    raise SystemExit(main())


if __name__ == "__main__":
    run()
