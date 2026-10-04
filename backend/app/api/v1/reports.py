"""Report endpoints.

Three ways to get the same report:

* ``GET /repositories/{id}/report`` — the report as data.
* ``GET /repositories/{id}/report/export?format=…`` — a rendered document
  wrapped in JSON, which is what the web interface uses to preview and save one.
* the same with ``download=true`` — the document itself, as a file, for
  ``curl -o`` and for a CI job.

A downloaded HTML report is user-influenced markup, so when this API serves one
directly it is always an **attachment** and always under a ``sandbox`` policy:
it is saved, not rendered on the API's own origin.
"""

from typing import Annotated

from fastapi import APIRouter, Query, Response

from app.core.deps import Context, CurrentUser, DbSession, ReportServiceDep
from app.reports.html import CONTENT_SECURITY_POLICY
from app.schemas.error import ErrorResponse
from app.schemas.report import ReportExportRead, ReportRead
from app.services.report_service import ReportFormat

router = APIRouter(tags=["reports"])

RESPONSES: dict[int | str, dict[str, object]] = {
    404: {
        "model": ErrorResponse,
        "description": "No such repository, or it belongs to someone else",
    },
    409: {
        "model": ErrorResponse,
        "description": "The repository has not been scanned yet",
    },
}


@router.get(
    "/repositories/{repository_id}/report",
    response_model=ReportRead,
    summary="A repository's security report, as data",
    responses=RESPONSES,
)
def repository_report(
    repository_id: int, user: CurrentUser, service: ReportServiceDep
) -> ReportRead:
    return ReportRead.from_report(service.build(repository_id, user))


@router.get(
    "/repositories/{repository_id}/report/export",
    response_model=ReportExportRead,
    summary="A repository's security report as Markdown, HTML, SARIF or JSON",
    responses=RESPONSES,
)
def export_repository_report(  # noqa: PLR0913 - one argument per dependency
    repository_id: int,
    user: CurrentUser,
    service: ReportServiceDep,
    context: Context,
    db: DbSession,
    export_format: Annotated[ReportFormat, Query(alias="format")] = ReportFormat.MARKDOWN,
    download: Annotated[bool, Query()] = False,
) -> ReportExportRead | Response:
    export = service.export(repository_id, user, export_format, context)
    # The audit row is the only write here, and it has to outlive the request.
    db.commit()
    if not download:
        return ReportExportRead(
            format=str(export.format),
            filename=export.filename,
            media_type=export.media_type,
            content=export.content,
        )
    return Response(
        content=export.content.encode("utf-8"),
        media_type=export.media_type,
        headers={
            # The filename is built from [a-z0-9-] only; see filename_for().
            "Content-Disposition": f'attachment; filename="{export.filename}"',
            "Content-Security-Policy": f"sandbox; {CONTENT_SECURITY_POLICY}",
            "Cache-Control": "no-store",
        },
    )
