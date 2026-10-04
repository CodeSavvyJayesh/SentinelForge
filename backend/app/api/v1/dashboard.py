"""The dashboard endpoint.

One read, no parameters, no queue. It takes no project or repository id, so
there is nothing a caller could pass to reach somebody else's data: the only
input is who is asking.
"""

from dataclasses import asdict

from fastapi import APIRouter

from app.core.deps import CurrentUser, DashboardServiceDep
from app.schemas.dashboard import (
    DashboardFinding,
    DashboardFixes,
    DashboardRead,
    DashboardRepository,
    DashboardTotals,
    DashboardTrendPoint,
)
from app.schemas.dashboard import DashboardWeakness as WeaknessRead
from app.services.dashboard_service import RankedFinding, RepositorySummary

router = APIRouter(tags=["dashboard"])


@router.get(
    "/dashboard",
    response_model=DashboardRead,
    summary="Everything the signed-in user owns, on one page",
)
def dashboard(user: CurrentUser, service: DashboardServiceDep) -> DashboardRead:
    result = service.for_user(user)
    return DashboardRead(
        generated_at=result.generated_at,
        policy_version=result.policy_version,
        totals=DashboardTotals(
            projects=result.projects,
            repositories=result.repositories_total,
            repositories_scanned=result.repositories_scanned,
            scans_completed=result.scans_completed,
            open_findings=result.open_findings,
            fixed_findings=result.fixed_findings,
        ),
        open_by_severity=result.open_by_severity,
        repositories=[_repository(item) for item in result.repositories],
        top_findings=[_finding(item) for item in result.top_findings],
        weaknesses=[WeaknessRead(**asdict(item)) for item in result.weaknesses],
        fixes=DashboardFixes(**asdict(result.fixes), labelled=result.fixes.labelled),
    )


def _repository(item: RepositorySummary) -> DashboardRepository:
    return DashboardRepository(
        repository_id=item.repository.id,
        project_id=item.project.id,
        project_name=item.project.name,
        origin=item.repository.origin,
        primary_language=item.repository.primary_language,
        score=item.score,
        grade=item.grade,
        open_findings=item.open_findings,
        fixed_findings=item.fixed_findings,
        counts_by_severity=item.counts_by_severity,
        last_scan_at=item.last_scan_at,
        trend=[DashboardTrendPoint(**asdict(point)) for point in item.trend],
    )


def _finding(item: RankedFinding) -> DashboardFinding:
    finding = item.finding
    return DashboardFinding(
        finding_id=finding.id,
        repository_id=item.repository.id,
        project_id=item.project.id,
        project_name=item.project.name,
        origin=item.repository.origin,
        rule_id=finding.rule_id,
        title=finding.title,
        severity=str(finding.severity),
        cwe_id=finding.cwe_id,
        file_path=finding.file_path,
        line_start=finding.line_start,
        score=item.risk.score,
        explanation=item.risk.explanation,
    )
