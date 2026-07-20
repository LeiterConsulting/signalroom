from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from threading import RLock
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

from ..config import ConfigStore
from ..schemas import CaseItemCreate, DetectionRepositorySettings
from .gitops_verifier import VerificationError, verify_path
from .repository_store import DetectionRepositoryStore
from .service import DetectionService

SAFE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,239}$")
SAFE_REMOTE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$")
COMMIT_SHA = re.compile(r"^[0-9a-f]{40,64}$")
PROTECTED_CONTROL_FILES = {
    ".github/workflows/signalroom-detection-policy.yml",
    ".signalroom/policy.json",
    ".signalroom/signalroom.pub",
    "tools/verify_signalroom_detection.py",
}


class RepositoryHandoffError(ValueError):
    pass


class DetectionRepositoryService:
    """Preview-bound, explicit Git handoff for approved detection changes."""

    def __init__(
        self,
        config: ConfigStore,
        detections: DetectionService,
        store: DetectionRepositoryStore,
        runtime_root: Path | str,
    ):
        self.config = config
        self.detections = detections
        self.store = store
        self.runtime_root = Path(runtime_root)
        self.preview_root = self.runtime_root / "previews"
        self.worktree_root = self.runtime_root / "worktrees"
        self.disabled_hooks_root = self.runtime_root / "disabled-git-hooks"
        self._case_lock = RLock()
        self.preview_root.mkdir(parents=True, exist_ok=True)
        self.worktree_root.mkdir(parents=True, exist_ok=True)
        self.disabled_hooks_root.mkdir(parents=True, exist_ok=True)

    def inspect(
        self,
        settings: DetectionRepositorySettings | None = None,
    ) -> dict[str, Any]:
        policy = settings or self.config.load().detection_repository
        result: dict[str, Any] = {
            "enabled": policy.enabled,
            "configured": bool(policy.path.strip()),
            "path": policy.path.strip(),
            "base_ref": policy.base_ref.strip(),
            "branch_prefix": policy.branch_prefix.strip(),
            "remote_name": policy.remote_name.strip(),
            "allow_push": policy.allow_push,
            "allow_draft_pull_request": policy.allow_draft_pull_request,
            "git_available": bool(shutil.which("git")),
            "github_cli_available": bool(shutil.which("gh")),
            "ready": False,
            "blocking_reason": "",
            "warnings": [],
        }
        if not result["configured"]:
            result["blocking_reason"] = "Choose an absolute local Git repository path."
            return result
        try:
            repository = self._repository(policy)
            base_commit = self._base_commit(repository, policy.base_ref)
            remotes = self._git_text(repository, "remote").splitlines()
            current_branch = self._git_text(
                repository,
                "symbolic-ref",
                "--short",
                "-q",
                "HEAD",
                check=False,
            ).strip()
            remote_ready = policy.remote_name in remotes
            if policy.allow_push and not remote_ready:
                result["warnings"].append(
                    f"Remote {policy.remote_name!r} is not configured."
                )
            if policy.allow_draft_pull_request and not policy.allow_push:
                result["warnings"].append(
                    "Draft pull requests require explicit remote push permission."
                )
            if policy.allow_draft_pull_request and not result["github_cli_available"]:
                result["warnings"].append(
                    "GitHub CLI is not installed; draft pull requests are unavailable."
                )
            result.update(
                {
                    "ready": True,
                    "repository_root": str(repository),
                    "base_commit": base_commit,
                    "current_branch": current_branch,
                    "remotes": remotes,
                    "remote_ready": remote_ready,
                }
            )
        except (OSError, RepositoryHandoffError) as exc:
            result["blocking_reason"] = str(exc)
        return result

    def preview(
        self,
        detection_id: str,
        expected_content_sha256: str,
    ) -> dict[str, Any]:
        policy = self.config.load().detection_repository
        if not policy.enabled:
            raise RepositoryHandoffError(
                "Detection repository handoff is disabled in workspace settings"
            )
        repository = self._repository(policy)
        base_commit = self._base_commit(repository, policy.base_ref)
        handoff_id = str(uuid4())
        archive_path = self.preview_root / f"{handoff_id}.zip"
        detection, _, verification, archive_sha256 = (
            self.detections.build_git_change_archive(
                detection_id,
                expected_content_sha256,
                archive_path,
            )
        )
        files = self._archive_files(archive_path)
        changes: list[dict[str, Any]] = []
        blocking_reasons: list[str] = []
        for name, body in sorted(files.items()):
            reason = self._symbolic_link_boundary(repository, base_commit, name)
            existing, mode = self._base_file(repository, base_commit, name)
            protected = name in PROTECTED_CONTROL_FILES
            new_sha256 = hashlib.sha256(body).hexdigest()
            if reason:
                status = "protected-conflict"
                blocking_reasons.append(reason)
            elif mode == "120000":
                status = "protected-conflict"
                blocking_reasons.append(
                    f"{name} is a symbolic link in the base commit."
                )
            elif mode and mode not in {"100644", "100755"}:
                status = "protected-conflict"
                blocking_reasons.append(
                    f"{name} is not a regular file in the base commit."
                )
            elif existing is None:
                status = "added"
            elif existing == body:
                status = "unchanged"
            elif protected:
                status = "protected-conflict"
                blocking_reasons.append(
                    f"{name} differs from the repository-owned policy control."
                )
            else:
                status = "modified"
            changes.append(
                {
                    "path": name,
                    "status": status,
                    "protected": protected,
                    "old_mode": mode,
                    "new_mode": (
                        mode if mode in {"100644", "100755"} else "100644"
                    ),
                    "old_sha256": (
                        hashlib.sha256(existing).hexdigest()
                        if existing is not None
                        else ""
                    ),
                    "new_sha256": new_sha256,
                    "bytes": len(body),
                }
            )
        changed = [item for item in changes if item["status"] != "unchanged"]
        if not changed:
            blocking_reasons.append(
                "The signed bundle does not change the selected base commit."
            )
        slug = DetectionService._slug(detection["content"]["title"])
        prefix = self._branch_prefix(policy.branch_prefix)
        branch_name = (
            f"{prefix}{slug}-v{detection['current_version']}-{handoff_id[:8]}"
        )
        self._validate_branch(repository, branch_name)
        if self._branch_commit(repository, branch_name):
            blocking_reasons.append(f"Local branch {branch_name} already exists.")
        created_at = datetime.now(UTC)
        expires_at = created_at + timedelta(minutes=30)
        summary = {
            status: sum(1 for item in changes if item["status"] == status)
            for status in ("added", "modified", "unchanged", "protected-conflict")
        }
        base_branch = self._base_branch(policy.base_ref, policy.remote_name)
        contract = {
            "schema_version": "signalroom-repository-preview/v1",
            "handoff_id": handoff_id,
            "detection_id": detection_id,
            "detection_title": detection["content"]["title"],
            "version": detection["current_version"],
            "content_sha256": detection["current_sha256"],
            "repository_path": str(repository),
            "base_ref": policy.base_ref,
            "base_branch": base_branch,
            "base_commit": base_commit,
            "branch_name": branch_name,
            "remote_name": policy.remote_name,
            "archive_sha256": archive_sha256,
            "signing_key_sha256": verification["key_id"],
            "commit_author": {
                "name": policy.commit_author_name.strip(),
                "email": policy.commit_author_email.strip(),
            },
            "files": changes,
            "summary": summary,
            "blocking_reasons": sorted(set(blocking_reasons)),
            "authority": {
                "changes_primary_worktree": False,
                "creates_local_branch": True,
                "creates_local_commit": True,
                "pushes_remote": False,
                "opens_pull_request": False,
                "deploys_to_splunk": False,
            },
            "created_at": created_at.isoformat(),
            "expires_at": expires_at.isoformat(),
        }
        preview_sha256 = self._sha256(self._canonical(contract))
        record = self.store.create(
            {
                "id": handoff_id,
                "detection_id": detection_id,
                "version": detection["current_version"],
                "content_sha256": detection["current_sha256"],
                "repository_path": str(repository),
                "base_ref": policy.base_ref,
                "base_commit": base_commit,
                "branch_name": branch_name,
                "archive_path": str(archive_path),
                "archive_sha256": archive_sha256,
                "signing_key_sha256": verification["key_id"],
                "preview_contract": contract,
                "preview_sha256": preview_sha256,
                "remote_name": policy.remote_name,
                "created_at": created_at.isoformat(),
                "expires_at": expires_at.isoformat(),
            }
        )
        return self.public(record)

    def apply(
        self,
        handoff_id: str,
        expected_preview_sha256: str,
    ) -> dict[str, Any]:
        record = self._record(handoff_id)
        if (
            record["status"] in {"applied", "pushed", "pull-request-opened"}
            and record["preview_sha256"] == expected_preview_sha256
        ):
            return self.public(record)
        self._validate_preview(record, expected_preview_sha256)
        contract = record["preview_contract"]
        if contract["blocking_reasons"]:
            raise RepositoryHandoffError(
                "Repository preview is blocked: "
                + "; ".join(contract["blocking_reasons"])
            )
        repository = self._repository_for_record(record)
        current_base = self._base_commit(repository, record["base_ref"])
        if current_base != record["base_commit"]:
            raise RepositoryHandoffError(
                "The repository base moved after preview; create a new preview"
            )
        if self._branch_commit(repository, record["branch_name"]):
            raise RepositoryHandoffError(
                f"Local branch {record['branch_name']} already exists"
            )
        archive = Path(record["archive_path"])
        if not archive.is_file():
            raise RepositoryHandoffError("Repository preview archive is unavailable")
        try:
            archive_sha256 = self._sha256(archive.read_bytes())
        except OSError as exc:
            raise RepositoryHandoffError(
                "Repository preview archive is unavailable"
            ) from exc
        if archive_sha256 != record["archive_sha256"]:
            raise RepositoryHandoffError("Repository preview archive changed after approval")
        try:
            verify_path(archive, record["signing_key_sha256"])
        except (OSError, VerificationError, json.JSONDecodeError) as exc:
            raise RepositoryHandoffError(
                f"Signed repository bundle verification failed: {exc}"
            ) from exc
        files = self._archive_files(archive)
        expected_files = {
            item["path"]: item["new_sha256"] for item in contract["files"]
        }
        actual_files = {
            name: hashlib.sha256(body).hexdigest() for name, body in files.items()
        }
        if actual_files != expected_files:
            raise RepositoryHandoffError(
                "Repository bundle no longer matches the approved preview"
            )
        worktree = self.worktree_root / handoff_id
        if worktree.exists():
            raise RepositoryHandoffError(
                "An isolated worktree already exists for this handoff"
            )
        worktree_created = False
        try:
            self._git(
                repository,
                "worktree",
                "add",
                "--detach",
                "--no-checkout",
                str(worktree),
                record["base_commit"],
                timeout=60,
            )
            worktree_created = True
            changed_paths = sorted(
                item["path"]
                for item in contract["files"]
                if item["status"] != "unchanged"
            )
            isolated_index = worktree / ".signalroom-index"
            index_environment = {"GIT_INDEX_FILE": str(isolated_index)}
            self._git(
                worktree,
                "read-tree",
                record["base_commit"],
                environment=index_environment,
            )
            change_by_path = {
                item["path"]: item
                for item in contract["files"]
                if item["status"] != "unchanged"
            }
            for name in changed_paths:
                blob_sha = self._git_text(
                    worktree,
                    "hash-object",
                    "-w",
                    "--stdin",
                    input_bytes=files[name],
                ).strip()
                if not COMMIT_SHA.fullmatch(blob_sha):
                    raise RepositoryHandoffError(
                        f"Git returned an invalid blob identifier for {name}"
                    )
                self._git(
                    worktree,
                    "update-index",
                    "--add",
                    "--cacheinfo",
                    (
                        f"{change_by_path[name]['new_mode']},"
                        f"{blob_sha},{name}"
                    ),
                    environment=index_environment,
                )
            tree_sha = self._git_text(
                worktree,
                "write-tree",
                environment=index_environment,
            ).strip()
            if not COMMIT_SHA.fullmatch(tree_sha):
                raise RepositoryHandoffError(
                    "Git returned an invalid repository tree identifier"
                )
            author = contract["commit_author"]
            self._validate_author(author["name"], author["email"])
            identity_environment = {
                "GIT_AUTHOR_NAME": author["name"],
                "GIT_AUTHOR_EMAIL": author["email"],
                "GIT_COMMITTER_NAME": author["name"],
                "GIT_COMMITTER_EMAIL": author["email"],
            }
            commit_sha = self._git_text(
                worktree,
                "commit-tree",
                tree_sha,
                "-p",
                record["base_commit"],
                "-m",
                (
                    f"Add SignalRoom detection: "
                    f"{contract['detection_title']} v{contract['version']}"
                ),
                environment=identity_environment,
            ).strip()
            if not COMMIT_SHA.fullmatch(commit_sha):
                raise RepositoryHandoffError("Git returned an invalid commit identifier")
            parent = self._git_text(worktree, "rev-parse", f"{commit_sha}^").strip()
            if parent != record["base_commit"]:
                raise RepositoryHandoffError(
                    "Created commit is not based on the approved repository commit"
                )
            committed_paths = {
                value
                for value in self._git_bytes(
                    worktree,
                    "diff-tree",
                    "--no-commit-id",
                    "--name-only",
                    "-r",
                    "-z",
                    commit_sha,
                )
                .decode("utf-8")
                .split("\0")
                if value
            }
            if committed_paths != set(changed_paths):
                raise RepositoryHandoffError(
                    "Committed repository paths do not match the approved preview"
                )
            self._verify_committed_files(
                repository,
                commit_sha,
                expected_files,
            )
            zero_commit = "0" * len(commit_sha)
            self._git(
                repository,
                "update-ref",
                f"refs/heads/{record['branch_name']}",
                commit_sha,
                zero_commit,
            )
        finally:
            if worktree_created or worktree.exists():
                self._git(
                    repository,
                    "worktree",
                    "remove",
                    "--force",
                    str(worktree),
                    check=False,
                    timeout=60,
                )
        result = self.store.mark_applied(
            handoff_id,
            expected_preview_sha256,
            commit_sha,
        )
        return self.public(result)

    def push(self, handoff_id: str, expected_commit_sha: str) -> dict[str, Any]:
        record = self._record(handoff_id)
        if (
            record["status"] in {"pushed", "pull-request-opened"}
            and record["commit_sha"] == expected_commit_sha
        ):
            return self.public(record)
        policy = self.config.load().detection_repository
        if not policy.enabled or not policy.allow_push:
            raise RepositoryHandoffError(
                "Remote repository push is disabled in workspace settings"
            )
        self._validate_commit(record, expected_commit_sha)
        repository = self._repository_for_record(record)
        if policy.remote_name != record["remote_name"]:
            raise RepositoryHandoffError(
                "The configured Git remote changed after preview; create a new preview"
            )
        self._remote_url(repository, record["remote_name"])
        branch_commit = self._branch_commit(repository, record["branch_name"])
        if branch_commit != expected_commit_sha:
            raise RepositoryHandoffError(
                "Local branch no longer points to the approved handoff commit"
            )
        self._git(
            repository,
            "push",
            "--porcelain",
            "--set-upstream",
            record["remote_name"],
            f"{record['branch_name']}:refs/heads/{record['branch_name']}",
            timeout=120,
        )
        remote_commit = self._remote_branch_commit(
            repository,
            record["remote_name"],
            record["branch_name"],
        )
        if remote_commit != expected_commit_sha:
            raise RepositoryHandoffError(
                "Remote branch does not match the approved local commit"
            )
        return self.public(self.store.mark_pushed(handoff_id, expected_commit_sha))

    def open_draft_pull_request(
        self,
        handoff_id: str,
        expected_commit_sha: str,
    ) -> dict[str, Any]:
        record = self._record(handoff_id)
        if (
            record["status"] == "pull-request-opened"
            and record["commit_sha"] == expected_commit_sha
            and record["pull_request_url"]
        ):
            return self.public(record)
        policy = self.config.load().detection_repository
        if (
            not policy.enabled
            or not policy.allow_push
            or not policy.allow_draft_pull_request
        ):
            raise RepositoryHandoffError(
                "Draft pull-request creation is disabled in workspace settings"
            )
        if not shutil.which("gh"):
            raise RepositoryHandoffError("GitHub CLI is not installed")
        self._validate_commit(record, expected_commit_sha)
        if record["status"] != "pushed":
            raise RepositoryHandoffError(
                "Push the exact handoff commit before opening a draft pull request"
            )
        repository = self._repository_for_record(record)
        remote_url = self._remote_url(repository, record["remote_name"])
        github_repository = self._github_repository(remote_url)
        remote_commit = self._remote_branch_commit(
            repository,
            record["remote_name"],
            record["branch_name"],
        )
        if remote_commit != expected_commit_sha:
            raise RepositoryHandoffError(
                "Remote branch moved after push; draft pull request was not created"
            )
        existing = self._existing_pull_request(
            repository,
            github_repository,
            record["branch_name"],
        )
        if existing:
            if existing.get("headRefOid") != expected_commit_sha:
                raise RepositoryHandoffError(
                    "An existing pull request points to a different head commit"
                )
            if not existing.get("isDraft"):
                raise RepositoryHandoffError(
                    "The existing pull request is no longer a draft"
                )
            url = str(existing.get("url") or "")
        else:
            contract = record["preview_contract"]
            archive_path = Path(record["archive_path"])
            if not archive_path.is_file():
                raise RepositoryHandoffError(
                    "Repository handoff archive is unavailable"
                )
            archive_files = self._archive_files(archive_path)
            body = archive_files["CHANGE_REQUEST.md"].decode("utf-8")
            command = self._command(
                "gh",
                "pr",
                "create",
                "--repo",
                github_repository,
                "--draft",
                "--base",
                contract["base_branch"],
                "--head",
                record["branch_name"],
                "--title",
                f"Detection: {contract['detection_title']} v{contract['version']}",
                "--body",
                body,
            )
            result = self._run(
                command,
                repository,
                timeout=120,
                environment={"GH_PROMPT_DISABLED": "1", "GIT_TERMINAL_PROMPT": "0"},
            )
            url = result.stdout.decode("utf-8", errors="replace").strip().splitlines()[-1]
        if not url.startswith("https://"):
            raise RepositoryHandoffError(
                "GitHub CLI did not return a pull-request URL"
            )
        return self.public(
            self.store.mark_pull_request(handoff_id, expected_commit_sha, url)
        )

    def refresh_pull_request(
        self,
        handoff_id: str,
        expected_commit_sha: str,
    ) -> dict[str, Any]:
        record = self._record(handoff_id)
        self._validate_commit(record, expected_commit_sha)
        if (
            record["status"] != "pull-request-opened"
            or not record["pull_request_url"]
        ):
            raise RepositoryHandoffError(
                "Open a draft pull request before refreshing repository feedback"
            )
        repository = self._repository_for_record(record)
        remote_url = self._remote_url(repository, record["remote_name"])
        github_repository = self._github_repository(remote_url)
        pull_request_number = self._pull_request_number(
            record["pull_request_url"],
            github_repository,
        )
        pull_request, checks = self._github_pull_request(
            repository,
            github_repository,
            record["pull_request_url"],
        )
        snapshot = self._review_snapshot(
            record,
            github_repository,
            pull_request_number,
            pull_request,
            checks,
        )
        snapshot_sha256 = self._sha256(self._canonical(snapshot))
        self.store.record_review(
            handoff_id,
            record["detection_id"],
            record["commit_sha"],
            snapshot_sha256,
            snapshot,
        )
        return self.public(record)

    def preserve_review_to_case(
        self,
        handoff_id: str,
        expected_snapshot_sha256: str,
    ) -> dict[str, Any]:
        record = self._record(handoff_id)
        if (
            record["status"] != "pull-request-opened"
            or not record["pull_request_url"]
        ):
            raise RepositoryHandoffError(
                "Repository feedback requires an opened pull request"
            )
        review = self.store.review_by_sha256(
            handoff_id,
            expected_snapshot_sha256,
        )
        if review is None:
            raise RepositoryHandoffError(
                "Repository feedback snapshot changed; refresh before preserving"
            )
        payload = {
            key: value
            for key, value in review.items()
            if key
            not in {
                "id",
                "handoff_id",
                "detection_id",
                "commit_sha",
                "snapshot_sha256",
                "case_item_id",
            }
        }
        if self._sha256(self._canonical(payload)) != expected_snapshot_sha256:
            raise RepositoryHandoffError(
                "Stored repository feedback snapshot is invalid"
            )
        if review["commit_sha"] != record["commit_sha"]:
            raise RepositoryHandoffError(
                "Repository feedback does not match the approved handoff commit"
            )
        if review["case_item_id"]:
            return self.public(record)
        detection = self.detections.store.get(record["detection_id"])
        if detection is None:
            raise RepositoryHandoffError("Linked detection is unavailable")
        case_id = detection.get("case_id")
        if not case_id or self.detections.cases.get(
            case_id, detection["tenant_scope_id"]
        ) is None:
            raise RepositoryHandoffError(
                "Link the detection to a case before preserving repository feedback"
            )
        with self._case_lock:
            latest = self.store.review(review["id"])
            assert latest is not None
            if latest["case_item_id"]:
                return self.public(record)
            item = self.detections.cases.add_item(
                case_id,
                self._review_case_item(detection, latest),
                detection["tenant_scope_id"],
            )
            if item is None:
                raise RepositoryHandoffError(
                    "Linked case is unavailable"
                )
            self.store.mark_review_preserved(review["id"], item.id)
        return self.public(record)

    def latest(self, detection_id: str) -> dict[str, Any] | None:
        value = self.store.latest(detection_id)
        return self.public(value) if value else None

    def public(self, record: dict[str, Any]) -> dict[str, Any]:
        contract = record["preview_contract"]
        return {
            "id": record["id"],
            "detection_id": record["detection_id"],
            "version": record["version"],
            "content_sha256": record["content_sha256"],
            "status": record["status"],
            "preview_sha256": record["preview_sha256"],
            "repository_path": record["repository_path"],
            "base_ref": record["base_ref"],
            "base_commit": record["base_commit"],
            "branch_name": record["branch_name"],
            "remote_name": record["remote_name"],
            "signing_key_sha256": record["signing_key_sha256"],
            "commit_sha": record["commit_sha"],
            "pull_request_url": record["pull_request_url"],
            "summary": contract["summary"],
            "files": contract["files"],
            "blocking_reasons": contract["blocking_reasons"],
            "authority": contract["authority"],
            "created_at": record["created_at"],
            "expires_at": record["expires_at"],
            "applied_at": record["applied_at"],
            "pushed_at": record["pushed_at"],
            "pull_request_at": record["pull_request_at"],
            "review": self.store.latest_review(record["id"]),
        }

    def _repository(self, policy: DetectionRepositorySettings) -> Path:
        if not shutil.which("git"):
            raise RepositoryHandoffError("Git is not installed or available on PATH")
        raw = policy.path.strip()
        path = Path(raw).expanduser()
        if not path.is_absolute():
            raise RepositoryHandoffError(
                "Detection repository path must be absolute"
            )
        try:
            path = path.resolve(strict=True)
        except OSError as exc:
            raise RepositoryHandoffError(
                f"Detection repository path is unavailable: {raw}"
            ) from exc
        if not path.is_dir():
            raise RepositoryHandoffError(
                "Detection repository path is not a directory"
            )
        root = Path(
            self._git_text(path, "rev-parse", "--show-toplevel").strip()
        ).resolve()
        if not self._same_path(root, path):
            raise RepositoryHandoffError(
                f"Configure the repository root directly: {root}"
            )
        self._validate_ref(policy.base_ref, "base ref")
        self._branch_prefix(policy.branch_prefix)
        if not SAFE_REMOTE.fullmatch(policy.remote_name.strip()):
            raise RepositoryHandoffError("Git remote name is invalid")
        self._validate_author(
            policy.commit_author_name.strip(),
            policy.commit_author_email.strip(),
        )
        return root

    def _repository_for_record(self, record: dict[str, Any]) -> Path:
        policy = self.config.load().detection_repository
        if not policy.enabled:
            raise RepositoryHandoffError(
                "Detection repository handoff is disabled in workspace settings"
            )
        repository = self._repository(policy)
        if not self._same_path(repository, Path(record["repository_path"])):
            raise RepositoryHandoffError(
                "Configured repository changed after preview; create a new preview"
            )
        return repository

    def _base_commit(self, repository: Path, base_ref: str) -> str:
        self._validate_ref(base_ref, "base ref")
        commit = self._git_text(
            repository,
            "rev-parse",
            "--verify",
            f"{base_ref.strip()}^{{commit}}",
        ).strip()
        if not COMMIT_SHA.fullmatch(commit):
            raise RepositoryHandoffError("Git returned an invalid base commit")
        return commit

    def _branch_commit(self, repository: Path, branch: str) -> str:
        value = self._git_text(
            repository,
            "rev-parse",
            "--verify",
            f"refs/heads/{branch}^{{commit}}",
            check=False,
        ).strip()
        return value if COMMIT_SHA.fullmatch(value) else ""

    def _validate_branch(self, repository: Path, branch: str) -> None:
        result = self._git_text(
            repository,
            "check-ref-format",
            "--branch",
            branch,
            check=False,
        ).strip()
        if result != branch:
            raise RepositoryHandoffError("Generated Git branch name is invalid")

    def _base_file(
        self,
        repository: Path,
        commit: str,
        name: str,
    ) -> tuple[bytes | None, str]:
        mode = self._tree_mode(repository, commit, name)
        if not mode:
            return None, ""
        value = self._git_bytes(
            repository,
            "show",
            f"{commit}:{name}",
            check=False,
        )
        return value, mode

    def _tree_mode(self, repository: Path, commit: str, name: str) -> str:
        output = self._git_text(
            repository,
            "ls-tree",
            commit,
            "--",
            name,
            check=False,
        ).strip()
        if not output:
            return ""
        return output.split(" ", 1)[0]

    def _symbolic_link_boundary(
        self,
        repository: Path,
        commit: str,
        name: str,
    ) -> str:
        parts = PurePosixPath(name).parts
        for index in range(1, len(parts)):
            parent = "/".join(parts[:index])
            if self._tree_mode(repository, commit, parent) == "120000":
                return f"{name} crosses symbolic-link path {parent}."
        return ""

    def _verify_committed_files(
        self,
        worktree: Path,
        commit_sha: str,
        expected: dict[str, str],
    ) -> None:
        for name, expected_sha256 in expected.items():
            body = self._git_bytes(
                worktree,
                "cat-file",
                "blob",
                f"{commit_sha}:{name}",
            )
            if self._sha256(body) != expected_sha256:
                raise RepositoryHandoffError(
                    f"Committed file does not match approved preview: {name}"
                )

    def _validate_preview(
        self,
        record: dict[str, Any],
        expected_preview_sha256: str,
    ) -> None:
        if record["status"] != "previewed":
            raise RepositoryHandoffError("Repository preview is no longer pending")
        if record["preview_sha256"] != expected_preview_sha256:
            raise RepositoryHandoffError(
                "Repository preview changed; review the latest exact diff"
            )
        recomputed = self._sha256(self._canonical(record["preview_contract"]))
        if recomputed != expected_preview_sha256:
            raise RepositoryHandoffError("Stored repository preview is invalid")
        expires_at = datetime.fromisoformat(
            record["expires_at"].replace("Z", "+00:00")
        )
        if datetime.now(UTC) >= expires_at.astimezone(UTC):
            raise RepositoryHandoffError(
                "Repository preview expired; create a new preview"
            )

    @staticmethod
    def _validate_commit(record: dict[str, Any], expected: str) -> None:
        if not COMMIT_SHA.fullmatch(expected):
            raise RepositoryHandoffError("Expected commit identifier is invalid")
        if record["commit_sha"] != expected:
            raise RepositoryHandoffError(
                "Repository handoff commit changed; review the latest state"
            )
        if record["status"] not in {
            "applied",
            "pushed",
            "pull-request-opened",
        }:
            raise RepositoryHandoffError(
                "Repository handoff does not have an approved local commit"
            )

    def _remote_url(self, repository: Path, remote: str) -> str:
        value = self._git_text(
            repository,
            "remote",
            "get-url",
            remote,
        ).strip()
        if not value:
            raise RepositoryHandoffError(f"Git remote {remote!r} has no URL")
        return value

    def _remote_branch_commit(
        self,
        repository: Path,
        remote: str,
        branch: str,
    ) -> str:
        output = self._git_text(
            repository,
            "ls-remote",
            remote,
            f"refs/heads/{branch}",
            timeout=120,
        ).strip()
        if not output:
            return ""
        commit = output.split()[0]
        return commit if COMMIT_SHA.fullmatch(commit) else ""

    def _existing_pull_request(
        self,
        repository: Path,
        github_repository: str,
        branch: str,
    ) -> dict[str, Any] | None:
        command = self._command(
            "gh",
            "pr",
            "view",
            branch,
            "--repo",
            github_repository,
            "--json",
            "url,isDraft,headRefOid",
        )
        result = self._run(
            command,
            repository,
            timeout=60,
            check=False,
            environment={"GH_PROMPT_DISABLED": "1", "GIT_TERMINAL_PROMPT": "0"},
        )
        if result.returncode:
            return None
        try:
            value = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise RepositoryHandoffError(
                "GitHub CLI returned invalid pull-request state"
            ) from exc
        return value if isinstance(value, dict) else None

    def _github_pull_request(
        self,
        repository: Path,
        github_repository: str,
        pull_request_url: str,
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        fields = ",".join(
            [
                "url",
                "number",
                "title",
                "state",
                "isDraft",
                "mergedAt",
                "headRefName",
                "headRefOid",
                "baseRefName",
                "baseRefOid",
                "reviewDecision",
                "mergeStateStatus",
                "mergeable",
                "updatedAt",
            ]
        )
        view = self._run(
            self._command(
                "gh",
                "pr",
                "view",
                pull_request_url,
                "--repo",
                github_repository,
                "--json",
                fields,
            ),
            repository,
            timeout=60,
            environment={
                "GH_PROMPT_DISABLED": "1",
                "GIT_TERMINAL_PROMPT": "0",
            },
        )
        try:
            pull_request = json.loads(view.stdout)
        except json.JSONDecodeError as exc:
            raise RepositoryHandoffError(
                "GitHub CLI returned invalid pull-request state"
            ) from exc
        if not isinstance(pull_request, dict):
            raise RepositoryHandoffError(
                "GitHub CLI returned an invalid pull-request record"
            )
        checks_result = self._run(
            self._command(
                "gh",
                "pr",
                "checks",
                pull_request_url,
                "--repo",
                github_repository,
                "--json",
                (
                    "name,state,bucket,workflow,description,"
                    "startedAt,completedAt"
                ),
            ),
            repository,
            timeout=60,
            check=False,
            environment={
                "GH_PROMPT_DISABLED": "1",
                "GIT_TERMINAL_PROMPT": "0",
            },
        )
        if checks_result.returncode not in {0, 8}:
            detail = checks_result.stderr.decode(
                "utf-8",
                errors="replace",
            ).strip()
            if "no checks reported" in detail.lower():
                return pull_request, []
            raise RepositoryHandoffError(
                f"GitHub check refresh failed: "
                f"{detail[-800:] or 'unknown error'}"
            )
        try:
            checks = json.loads(checks_result.stdout or b"[]")
        except json.JSONDecodeError as exc:
            raise RepositoryHandoffError(
                "GitHub CLI returned invalid check state"
            ) from exc
        if not isinstance(checks, list):
            raise RepositoryHandoffError(
                "GitHub CLI returned an invalid check collection"
            )
        return pull_request, [
            item for item in checks if isinstance(item, dict)
        ]

    def _review_snapshot(
        self,
        record: dict[str, Any],
        github_repository: str,
        pull_request_number: int,
        pull_request: dict[str, Any],
        checks: list[dict[str, Any]],
    ) -> dict[str, Any]:
        returned_url = self._bounded_text(pull_request.get("url"), 1000)
        if returned_url != record["pull_request_url"]:
            raise RepositoryHandoffError(
                "GitHub returned a different pull-request identity"
            )
        returned_number = pull_request.get("number")
        if (
            isinstance(returned_number, bool)
            or not isinstance(returned_number, int)
            or returned_number != pull_request_number
        ):
            raise RepositoryHandoffError(
                "GitHub returned a different pull-request number"
            )
        head_oid = self._bounded_text(pull_request.get("headRefOid"), 64).lower()
        head_ref = self._bounded_text(pull_request.get("headRefName"), 240)
        commit_matches = (
            bool(COMMIT_SHA.fullmatch(head_oid))
            and head_oid == record["commit_sha"]
        )
        branch_matches = head_ref == record["branch_name"]
        identity_status = (
            "exact" if commit_matches and branch_matches else "stale"
        )
        normalized_checks: list[dict[str, str]] = []
        counts = {
            "pass": 0,
            "fail": 0,
            "pending": 0,
            "skipping": 0,
            "cancel": 0,
            "unknown": 0,
        }
        for item in checks[:100]:
            bucket = self._bounded_text(item.get("bucket"), 40).lower()
            if bucket not in counts:
                bucket = "unknown"
            counts[bucket] += 1
            normalized_checks.append(
                {
                    "name": self._bounded_text(item.get("name"), 240)
                    or "Unnamed check",
                    "workflow": self._bounded_text(
                        item.get("workflow"),
                        240,
                    ),
                    "state": self._bounded_text(item.get("state"), 80),
                    "bucket": bucket,
                    "description": self._bounded_text(
                        item.get("description"),
                        500,
                    ),
                    "started_at": self._bounded_text(
                        item.get("startedAt"),
                        80,
                    ),
                    "completed_at": self._bounded_text(
                        item.get("completedAt"),
                        80,
                    ),
                }
            )
        if counts["fail"] or counts["cancel"]:
            checks_status = "fail"
        elif counts["pending"] or counts["unknown"]:
            checks_status = "pending"
        elif normalized_checks:
            checks_status = "pass"
        else:
            checks_status = "none"
        review_decision = self._bounded_text(
            pull_request.get("reviewDecision"),
            80,
        ).upper()
        if review_decision not in {
            "APPROVED",
            "CHANGES_REQUESTED",
            "REVIEW_REQUIRED",
        }:
            review_decision = "REVIEW_REQUIRED"
        state = self._bounded_text(pull_request.get("state"), 40).upper()
        merged_at = self._bounded_text(pull_request.get("mergedAt"), 80)
        is_draft = bool(pull_request.get("isDraft"))
        if merged_at or state == "MERGED":
            lifecycle = "merged"
        elif state == "CLOSED":
            lifecycle = "closed"
        elif is_draft:
            lifecycle = "draft"
        else:
            lifecycle = "open"
        if identity_status != "exact":
            risk_level = "critical"
            recommended_action = (
                "Stop promotion: the pull-request head no longer matches the "
                "approved SignalRoom branch and commit. Inspect the remote diff."
            )
        elif lifecycle == "merged":
            risk_level = "low"
            recommended_action = (
                "The exact observed commit merged. Confirm downstream deployment "
                "and Splunk saved-search state independently."
            )
        elif lifecycle == "closed":
            risk_level = "high"
            recommended_action = (
                "The pull request closed without an observed merge. Decide whether "
                "to revise, supersede, or retire this detection handoff."
            )
        elif checks_status == "fail":
            risk_level = "high"
            recommended_action = (
                "Resolve failed or cancelled repository checks before requesting "
                "promotion."
            )
        elif review_decision == "CHANGES_REQUESTED":
            risk_level = "high"
            recommended_action = (
                "Address requested review changes, then create a new SignalRoom "
                "preview if the approved detection content changes."
            )
        elif (
            lifecycle == "draft"
            or checks_status in {"pending", "none"}
            or review_decision == "REVIEW_REQUIRED"
        ):
            risk_level = "medium"
            recommended_action = (
                "Repository review is incomplete. Wait for required checks and "
                "reviewers, then refresh explicitly."
            )
        else:
            risk_level = "low"
            recommended_action = (
                "Observed checks and review are ready. Merge remains controlled "
                "by repository policy outside SignalRoom."
            )
        return {
            "schema_version": "signalroom-repository-review/v1",
            "provider": "github",
            "repository": github_repository,
            "pull_request_url": returned_url,
            "pull_request_number": pull_request_number,
            "title": self._bounded_text(pull_request.get("title"), 240),
            "lifecycle": lifecycle,
            "is_draft": is_draft,
            "merged_at": merged_at,
            "updated_at": self._bounded_text(
                pull_request.get("updatedAt"),
                80,
            ),
            "review_decision": review_decision.lower().replace("_", "-"),
            "merge_state_status": self._bounded_text(
                pull_request.get("mergeStateStatus"),
                80,
            ).lower(),
            "mergeable": self._bounded_text(
                pull_request.get("mergeable"),
                80,
            ).lower(),
            "head_ref_name": head_ref,
            "head_ref_oid": head_oid,
            "base_ref_name": self._bounded_text(
                pull_request.get("baseRefName"),
                240,
            ),
            "base_ref_oid": self._bounded_text(
                pull_request.get("baseRefOid"),
                64,
            ).lower(),
            "expected_branch": record["branch_name"],
            "expected_commit_sha": record["commit_sha"],
            "identity_status": identity_status,
            "checks_status": checks_status,
            "check_counts": counts,
            "checks": normalized_checks,
            "risk_level": risk_level,
            "recommended_action": recommended_action,
            "authority": {
                "read_only_refresh": True,
                "changes_repository": False,
                "merges_pull_request": False,
                "deploys_to_splunk": False,
                "proves_splunk_deployment": False,
            },
            "observed_at": datetime.now(UTC).isoformat(),
        }

    def _review_case_item(
        self,
        detection: dict[str, Any],
        review: dict[str, Any],
    ) -> CaseItemCreate:
        counts = review["check_counts"]
        return CaseItemCreate(
            kind=(
                "decision"
                if review["lifecycle"] in {"merged", "closed"}
                else "action"
            ),
            title=(
                f"Repository feedback · "
                f"{detection['content']['title']} · "
                f"{review['lifecycle']}"
            ),
            content=(
                f"Explicit GitHub observation: {review['observed_at']}\n\n"
                f"Pull request: {review['pull_request_url']}\n"
                f"Approved commit: {review['expected_commit_sha']}\n"
                f"Observed head: {review['head_ref_oid'] or 'unavailable'}\n"
                f"Identity: {review['identity_status']}\n"
                f"Lifecycle: {review['lifecycle']}\n"
                f"Review: {review['review_decision']}\n"
                f"Checks: {review['checks_status']} "
                f"({counts['pass']} pass, {counts['fail']} fail, "
                f"{counts['pending']} pending, {counts['cancel']} cancelled)\n\n"
                f"Next: {review['recommended_action']}\n\n"
                "This snapshot records repository state only. It does not prove "
                "that the detection was deployed or enabled in Splunk."
            ),
            source="SignalRoom repository feedback",
            confidence="high",
            status=(
                "complete"
                if review["lifecycle"] in {"merged", "closed"}
                else "needs-validation"
            ),
            occurred_at=review["observed_at"],
            metadata={
                "detection_id": detection["id"],
                "detection_repository_handoff_id": review["handoff_id"],
                "repository_review_id": review["id"],
                "repository_review_sha256": review["snapshot_sha256"],
                "commit_sha": review["expected_commit_sha"],
                "pull_request_url": review["pull_request_url"],
                "risk_level": review["risk_level"],
                "identity_status": review["identity_status"],
                "lifecycle": review["lifecycle"],
            },
        )

    @staticmethod
    def _pull_request_number(
        pull_request_url: str,
        github_repository: str,
    ) -> int:
        parsed = urlparse(pull_request_url.strip())
        parts = [part for part in parsed.path.split("/") if part]
        expected = github_repository.split("/", 1)
        if (
            parsed.scheme != "https"
            or parsed.hostname not in {"github.com", "www.github.com"}
            or len(parts) != 4
            or [parts[0].lower(), parts[1].lower()]
            != [expected[0].lower(), expected[1].lower()]
            or parts[2] != "pull"
            or not parts[3].isdigit()
        ):
            raise RepositoryHandoffError(
                "Stored pull-request URL does not match the configured GitHub repository"
            )
        number = int(parts[3])
        if number < 1:
            raise RepositoryHandoffError("Pull-request number is invalid")
        return number

    @staticmethod
    def _bounded_text(value: Any, limit: int) -> str:
        return str(value or "").strip()[:limit]

    @staticmethod
    def _github_repository(remote_url: str) -> str:
        value = remote_url.strip()
        if value.startswith("git@github.com:"):
            path = value.split(":", 1)[1]
        else:
            parsed = urlparse(value)
            if parsed.hostname not in {"github.com", "www.github.com"}:
                raise RepositoryHandoffError(
                    "Draft pull requests require a github.com Git remote"
                )
            path = parsed.path.lstrip("/")
        if path.endswith(".git"):
            path = path[:-4]
        if not re.fullmatch(r"[^/\s]+/[^/\s]+", path):
            raise RepositoryHandoffError("GitHub repository remote is invalid")
        return path

    @staticmethod
    def _archive_files(path: Path) -> dict[str, bytes]:
        files: dict[str, bytes] = {}
        with zipfile.ZipFile(path) as archive:
            names = [item.filename for item in archive.infolist() if not item.is_dir()]
            if len(names) != len(set(names)):
                raise RepositoryHandoffError(
                    "Signed repository bundle contains duplicate paths"
                )
            for name in names:
                relative = DetectionRepositoryService._safe_relative(name)
                files[relative.as_posix()] = archive.read(name)
        return files

    @staticmethod
    def _safe_relative(name: str) -> PurePosixPath:
        value = PurePosixPath(name)
        if (
            "\\" in name
            or value.is_absolute()
            or ".." in value.parts
            or not value.parts
        ):
            raise RepositoryHandoffError(f"Unsafe repository bundle path: {name}")
        return value

    @staticmethod
    def _validate_ref(value: str, label: str) -> None:
        item = value.strip()
        if (
            not SAFE_REF.fullmatch(item)
            or ".." in item
            or "@{" in item
            or "//" in item
            or item.endswith(("/", ".", ".lock"))
        ):
            raise RepositoryHandoffError(f"Git {label} is invalid")

    @classmethod
    def _branch_prefix(cls, value: str) -> str:
        prefix = value.strip()
        if not prefix.endswith("/"):
            prefix = f"{prefix}/"
        cls._validate_ref(f"{prefix}preview", "branch prefix")
        return prefix

    @staticmethod
    def _base_branch(base_ref: str, remote_name: str) -> str:
        value = base_ref.strip()
        if value.startswith("refs/heads/"):
            return value.removeprefix("refs/heads/")
        if value.startswith(f"{remote_name}/"):
            return value.removeprefix(f"{remote_name}/")
        return value

    @staticmethod
    def _validate_author(name: str, email: str) -> None:
        if not name or any(character in name for character in "\r\n"):
            raise RepositoryHandoffError("Git commit author name is invalid")
        if (
            "@" not in email
            or email.startswith("@")
            or email.endswith("@")
            or any(character in email for character in "\r\n<>")
        ):
            raise RepositoryHandoffError("Git commit author email is invalid")

    def _record(self, handoff_id: str) -> dict[str, Any]:
        value = self.store.get(handoff_id)
        if value is None:
            raise KeyError("Repository handoff not found")
        return value

    @staticmethod
    def _canonical(value: dict[str, Any]) -> bytes:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode()

    @staticmethod
    def _sha256(value: bytes) -> str:
        return hashlib.sha256(value).hexdigest()

    @staticmethod
    def _same_path(left: Path, right: Path) -> bool:
        return os.path.normcase(str(left.resolve())) == os.path.normcase(
            str(right.resolve())
        )

    def _git_text(
        self,
        repository: Path,
        *arguments: str,
        check: bool = True,
        timeout: int = 30,
        environment: dict[str, str] | None = None,
        input_bytes: bytes | None = None,
    ) -> str:
        return self._git_bytes(
            repository,
            *arguments,
            check=check,
            timeout=timeout,
            environment=environment,
            input_bytes=input_bytes,
        ).decode("utf-8", errors="replace")

    def _git_bytes(
        self,
        repository: Path,
        *arguments: str,
        check: bool = True,
        timeout: int = 30,
        environment: dict[str, str] | None = None,
        input_bytes: bytes | None = None,
    ) -> bytes:
        result = self._git(
            repository,
            *arguments,
            check=check,
            timeout=timeout,
            environment=environment,
            input_bytes=input_bytes,
        )
        return result.stdout

    def _git(
        self,
        repository: Path,
        *arguments: str,
        check: bool = True,
        timeout: int = 30,
        environment: dict[str, str] | None = None,
        input_bytes: bytes | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        git_environment = {"GIT_TERMINAL_PROMPT": "0"}
        git_environment.update(environment or {})
        return self._run(
            self._command(
                "git",
                "-c",
                f"core.hooksPath={self.disabled_hooks_root.resolve()}",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "protocol.ext.allow=never",
                *arguments,
            ),
            repository,
            check=check,
            timeout=timeout,
            environment=git_environment,
            input_bytes=input_bytes,
        )

    @staticmethod
    def _command(executable: str, *arguments: str) -> list[str]:
        path = shutil.which(executable)
        if not path:
            raise RepositoryHandoffError(
                f"{executable} is not installed or available on PATH"
            )
        return [path, *arguments]

    @staticmethod
    def _run(
        command: list[str],
        repository: Path,
        *,
        check: bool = True,
        timeout: int = 30,
        environment: dict[str, str] | None = None,
        input_bytes: bytes | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        values = os.environ.copy()
        values.update(environment or {})
        try:
            result = subprocess.run(
                command,
                cwd=repository,
                capture_output=True,
                timeout=timeout,
                check=False,
                shell=False,
                env=values,
                input=input_bytes,
                creationflags=(
                    subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
                ),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RepositoryHandoffError(
                f"Repository command failed to start: {type(exc).__name__}"
            ) from exc
        if check and result.returncode:
            detail = result.stderr.decode("utf-8", errors="replace").strip()
            detail = detail or result.stdout.decode(
                "utf-8", errors="replace"
            ).strip()
            raise RepositoryHandoffError(
                f"Repository command failed: {detail[-1200:] or 'unknown error'}"
            )
        return result
