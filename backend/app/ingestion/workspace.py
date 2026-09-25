"""Isolated workspaces for ingested code.

Every repository gets its own directory under the configured workspace root.
Nothing is ever written outside that root, and deletion is refused for any path
that is not inside it — a belt-and-braces check, because a bug that deletes
arbitrary directories is unrecoverable.
"""

import secrets
import shutil
from pathlib import Path

from app.core.config import Settings
from app.core.logging import get_logger

logger = get_logger("sentinelforge.workspace")


class WorkspaceManager:
    def __init__(self, settings: Settings) -> None:
        self.root = Path(settings.WORKSPACE_ROOT).resolve()

    def create(self, *, project_id: int, repository_id: int) -> tuple[Path, str]:
        """Create an empty workspace; returns the absolute path and the
        relative path stored in the database."""
        relative = f"project-{project_id}/repo-{repository_id}-{secrets.token_hex(4)}"
        path = (self.root / relative).resolve()
        self._assert_inside_root(path)
        path.mkdir(parents=True, exist_ok=False)
        logger.info(
            "workspace_created",
            extra={"project_id": project_id, "repository_id": repository_id, "path": relative},
        )
        return path, relative

    def absolute(self, relative: str) -> Path:
        path = (self.root / relative).resolve()
        self._assert_inside_root(path)
        return path

    def remove(self, relative: str | None) -> None:
        """Delete a workspace. Silently ignores an already-missing directory."""
        if not relative:
            return
        path = (self.root / relative).resolve()
        self._assert_inside_root(path)
        if path.exists():
            shutil.rmtree(path, ignore_errors=True)
            logger.info("workspace_removed", extra={"path": relative})

    def _assert_inside_root(self, path: Path) -> None:
        if path != self.root and self.root not in path.parents:
            # Defensive: reaching here means a bug or a traversal attempt.
            raise ValueError(f"Refusing to touch a path outside the workspace root: {path}")
