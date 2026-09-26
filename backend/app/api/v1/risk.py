"""Risk endpoints.

Both are reads, and both are cheap: the score is arithmetic over findings the
database already holds. There is no queue and no worker here, because there is
nothing slow to defer — which is itself the argument for Phase 9 being
deterministic rather than another model call.
"""

from fastapi import APIRouter, Query

from app.core.deps import CurrentUser, RiskServiceDep
from app.models import Finding
from app.schemas.error import ErrorResponse
from app.schemas.risk import (
    FindingRiskRead,
    RepositoryRiskRead,
    RiskFactor,
    RiskHistoryRead,
    RiskPointRead,
)

router = APIRouter(tags=["risk"])

NOT_FOUND_RESPONSE: dict[int | str, dict[str, object]] = {
    404: {
        "model": ErrorResponse,
        "description": "No such repository, or it belongs to someone else",
    },
}


@router.get(
    "/repositories/{repository_id}/risk",
    response_model=RepositoryRiskRead,
    summary="The current risk score for a repository, with its working",
    responses=NOT_FOUND_RESPONSE,
)
def repository_risk(
    repository_id: int,
    user: CurrentUser,
    service: RiskServiceDep,
    top: int = Query(default=5, ge=1, le=50),
) -> RepositoryRiskRead:
    repository, risk = service.for_repository(repository_id, user, top=top)
    findings = {finding.id: finding for finding in service.findings.list_all(repository.id)}
    return RepositoryRiskRead(
        repository_id=repository.id,
        score=risk.score,
        grade=risk.grade,
        policy_version=risk.policy_version,
        finding_count=risk.finding_count,
        counts_by_severity=risk.counts_by_severity,
        top=[_to_read(item, findings.get(item.finding_id)) for item in risk.top],
    )


@router.get(
    "/repositories/{repository_id}/risk/history",
    response_model=RiskHistoryRead,
    summary="Risk over time, one point per completed scan",
    responses=NOT_FOUND_RESPONSE,
)
def repository_risk_history(
    repository_id: int,
    user: CurrentUser,
    service: RiskServiceDep,
    limit: int = Query(default=20, ge=1, le=100),
) -> RiskHistoryRead:
    scans = service.history(repository_id, user, limit=limit)
    return RiskHistoryRead(
        repository_id=repository_id,
        points=[
            RiskPointRead(
                scan_id=scan.id,
                score=scan.risk_score or 0.0,
                grade=scan.risk_grade or "?",
                policy_version=scan.risk_policy_version,
                total_findings=scan.total_findings,
                finished_at=scan.finished_at,
            )
            for scan in scans
        ],
    )


def _to_read(item, finding: Finding | None) -> FindingRiskRead:  # noqa: ANN001 - FindingRisk
    return FindingRiskRead(
        finding_id=item.finding_id,
        score=item.score,
        base=item.base,
        factors=[
            RiskFactor(name=factor.name, value=factor.value, reason=factor.reason)
            for factor in item.factors
        ],
        explanation=item.explanation,
        title=finding.title if finding else "",
        severity=str(finding.severity) if finding else "",
        file_path=finding.file_path if finding else "",
        line_start=finding.line_start if finding else 0,
    )
