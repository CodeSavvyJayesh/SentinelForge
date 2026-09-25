"""Scan request/response schemas.

A queued scan is returned with `202 Accepted`, not `200`: the work has been
accepted, not done. The client polls `GET /scans/{id}` until the status leaves
`QUEUED`/`RUNNING`.
"""

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models.scan import ScanStatus


class ScanRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    repository_id: int
    status: ScanStatus
    attempts: int
    started_at: datetime | None
    finished_at: datetime | None
    duration_ms: int | None
    files_scanned: int
    files_skipped: int
    unparsable_files: int
    # What this run concluded, frozen at the time it ran — a history row must
    # still be true after the findings have moved on.
    total_findings: int
    new_findings: int
    fixed_findings: int
    truncated: bool
    error_message: str | None
    created_at: datetime


class ScanListResponse(BaseModel):
    items: list[ScanRead]
    total: int
    limit: int
    offset: int
