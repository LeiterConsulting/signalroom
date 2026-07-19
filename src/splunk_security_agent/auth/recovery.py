from __future__ import annotations

import argparse
import getpass
import os
from pathlib import Path

from ..audit import AuditStore
from .service import AuthService
from .store import AuthStore


def _default_data_dir() -> Path:
    root = Path(os.getenv("SIGNALROOM_ROOT", Path.cwd())).resolve()
    return Path(os.getenv("SIGNALROOM_DATA_DIR", root / "data")).resolve()


def run() -> None:
    parser = argparse.ArgumentParser(
        prog="signalroom-access",
        description=(
            "Host-only SignalRoom local-account recovery. This command never "
            "changes an OIDC identity."
        ),
    )
    parser.add_argument(
        "command",
        choices=["reset-password"],
        help="Recovery operation to perform",
    )
    parser.add_argument("--username", required=True, help="Active local username")
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=_default_data_dir(),
        help="SignalRoom data directory containing auth.db and audit.db",
    )
    parser.add_argument(
        "--confirm-local-host-access",
        action="store_true",
        help="Confirm that you are authorized to administer this SignalRoom host",
    )
    args = parser.parse_args()
    if not args.confirm_local_host_access:
        parser.error("--confirm-local-host-access is required")
    password = getpass.getpass("New local password (at least 12 characters): ")
    confirmation = getpass.getpass("Confirm new local password: ")
    if password != confirmation:
        parser.error("The password confirmation did not match")
    data = args.data_dir.resolve()
    service = AuthService(
        AuthStore(data / "auth.db"),
        AuditStore(data / "audit.db"),
    )
    try:
        user = service.recover_local_password(args.username, password)
    except ValueError as exc:
        parser.error(str(exc))
    print(
        f"Recovered local account {user['username']}; "
        "all of its browser sessions were revoked."
    )


if __name__ == "__main__":
    run()
