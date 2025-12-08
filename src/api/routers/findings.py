from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import and_, case, func
from typing import List, Optional, Dict
from ..database import get_db
from .. import models
from pydantic import BaseModel
from datetime import datetime
import uuid
import logging

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/findings",
    tags=["findings"]
)

# Severity priority for sorting (lower = higher priority)
SEVERITY_PRIORITY = {
    'critical': 1,
    'high': 2,
    'medium': 3,
    'low': 4,
    'info': 5,
    'warning': 6
}

class RemediationModel(BaseModel):
    id: str
    remediation_text: str
    diff: Optional[str]
    confidence: Optional[float]
    created_at: datetime

    model_config = {"from_attributes": True}

class FindingResponse(BaseModel):
    id: str
    title: str
    description: Optional[str]
    severity: str
    status: str
    scanner_name: Optional[str]
    file_path: Optional[str]
    line_start: Optional[int]
    code_snippet: Optional[str]
    created_at: datetime
    repo_pushed_at: Optional[datetime] = None  # Last push to repo (from GitHub API)
    file_last_commit_at: Optional[datetime] = None  # Last commit to specific file
    file_last_commit_author: Optional[str] = None  # Author of last file commit
    repo_name: str
    repository_id: Optional[str] = None
    is_archived: Optional[bool] = None  # Is the repo archived
    investigation_status: Optional[str] = None  # triage, incident_response, resolved
    investigation_started_at: Optional[datetime] = None
    remediations: List[RemediationModel] = []

    model_config = {"from_attributes": True}

@router.get("/", response_model=List[FindingResponse])
def get_findings(
    skip: int = 0, 
    limit: int = 100, 
    severity: Optional[str] = None,
    status: Optional[str] = None,
    repo_name: Optional[str] = None,
    order_by: Optional[str] = "severity",  # "severity", "created_at", "repo_name"
    db: Session = Depends(get_db)
):
    """Get all findings with optional filtering.
    
    Args:
        skip: Number of records to skip (pagination)
        limit: Maximum number of records to return
        severity: Filter by severity (critical, high, medium, low, info)
        status: Filter by status (open, resolved, etc.)
        repo_name: Filter by repository name
        order_by: Sort order - "severity" (default), "created_at", or "repo_name"
    """
    query = db.query(models.Finding).join(models.Repository)
    
    if severity:
        query = query.filter(models.Finding.severity == severity)
    
    if status:
        query = query.filter(models.Finding.status == status)
    
    if repo_name:
        query = query.filter(models.Repository.name == repo_name)
    
    # Order by severity priority, then by created_at
    if order_by == "severity":
        severity_order = case(
            (models.Finding.severity == 'critical', 1),
            (models.Finding.severity == 'high', 2),
            (models.Finding.severity == 'medium', 3),
            (models.Finding.severity == 'low', 4),
            (models.Finding.severity == 'info', 5),
            (models.Finding.severity == 'warning', 6),
            else_=7
        )
        query = query.order_by(severity_order, models.Finding.created_at.desc())
    elif order_by == "repo_name":
        query = query.order_by(models.Repository.name, models.Finding.created_at.desc())
    else:  # created_at
        query = query.order_by(models.Finding.created_at.desc())
    
    # Apply pagination - limit=0 means no limit (fetch all)
    if skip > 0:
        query = query.offset(skip)
    if limit > 0:
        query = query.limit(limit)
        
    findings = query.all()
    
    # Get file commit data for findings with file_paths (batch query)
    file_commits_map: Dict[str, models.FileCommit] = {}
    finding_file_keys = [
        (f.repository_id, f.file_path) 
        for f in findings 
        if f.repository_id and f.file_path
    ]
    if finding_file_keys:
        # Query all file commits in one go
        file_commits = db.query(models.FileCommit).filter(
            models.FileCommit.repository_id.in_([k[0] for k in finding_file_keys])
        ).all()
        for fc in file_commits:
            key = f"{fc.repository_id}:{fc.file_path}"
            file_commits_map[key] = fc
    
    return [FindingResponse(
        id=str(f.finding_uuid),
        title=f.title,
        description=f.description,
        severity=f.severity,
        status=f.status,
        scanner_name=f.scanner_name,
        file_path=f.file_path,
        line_start=f.line_start,
        code_snippet=f.code_snippet,
        created_at=f.created_at,
        repo_pushed_at=f.repository.pushed_at if f.repository else None,
        file_last_commit_at=file_commits_map.get(f"{f.repository_id}:{f.file_path}").last_commit_date if f.repository_id and f.file_path and f"{f.repository_id}:{f.file_path}" in file_commits_map else None,
        file_last_commit_author=file_commits_map.get(f"{f.repository_id}:{f.file_path}").last_commit_author if f.repository_id and f.file_path and f"{f.repository_id}:{f.file_path}" in file_commits_map else None,
        repo_name=f.repository.name if f.repository else "Unknown",
        repository_id=str(f.repository.id) if f.repository else None,
        is_archived=f.repository.is_archived if f.repository else None,
        investigation_status=f.investigation_status,
        investigation_started_at=f.investigation_started_at,
        remediations=[RemediationModel(
            id=str(r.id),
            remediation_text=r.remediation_text,
            diff=r.diff,
            confidence=float(r.confidence) if r.confidence else None,
            created_at=r.created_at
        ) for r in f.remediations]
    ) for f in findings]

@router.get("/{finding_id}", response_model=FindingResponse)
def get_finding(finding_id: str, db: Session = Depends(get_db)):
    """Get a specific finding by UUID."""
    # Try to parse UUID
    try:
        uuid_obj = uuid.UUID(finding_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")

    finding = db.query(models.Finding).filter(models.Finding.finding_uuid == uuid_obj).first()
    if not finding:
        # Fallback to check primary key id if finding_uuid fails (though model uses finding_uuid for public access usually)
        finding = db.query(models.Finding).filter(models.Finding.id == uuid_obj).first()
        
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Get file commit data if available
    file_commit = None
    if finding.repository_id and finding.file_path:
        file_commit = db.query(models.FileCommit).filter(
            models.FileCommit.repository_id == finding.repository_id,
            models.FileCommit.file_path == finding.file_path
        ).first()

    return FindingResponse(
        id=str(finding.finding_uuid),
        title=finding.title,
        description=finding.description,
        severity=finding.severity,
        status=finding.status,
        scanner_name=finding.scanner_name,
        file_path=finding.file_path,
        line_start=finding.line_start,
        code_snippet=finding.code_snippet,
        created_at=finding.created_at,
        repo_pushed_at=finding.repository.pushed_at if finding.repository else None,
        file_last_commit_at=file_commit.last_commit_date if file_commit else None,
        file_last_commit_author=file_commit.last_commit_author if file_commit else None,
        repo_name=finding.repository.name if finding.repository else "Unknown",
        repository_id=str(finding.repository.id) if finding.repository else None,
        is_archived=finding.repository.is_archived if finding.repository else None,
        investigation_status=finding.investigation_status,
        investigation_started_at=finding.investigation_started_at,
        remediations=[RemediationModel(
            id=str(r.id),
            remediation_text=r.remediation_text,
            diff=r.diff,
            confidence=float(r.confidence) if r.confidence else None,
            created_at=r.created_at
        ) for r in finding.remediations]
    )


# =============================================================================
# Finding Update Models and Endpoints
# =============================================================================

class FindingUpdateRequest(BaseModel):
    """Request to update a finding's fields."""
    description: Optional[str] = None

class FindingUpdateResponse(BaseModel):
    """Response after updating a finding."""
    id: str
    message: str
    updated_fields: List[str]
    version_id: Optional[str] = None


@router.patch("/{finding_id}", response_model=FindingUpdateResponse)
def update_finding(finding_id: str, update: FindingUpdateRequest, db: Session = Depends(get_db)):
    """Update a specific finding by UUID. Saves previous description to version history."""
    # Try to parse UUID
    try:
        uuid_obj = uuid.UUID(finding_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")

    finding = db.query(models.Finding).filter(models.Finding.finding_uuid == uuid_obj).first()
    if not finding:
        # Fallback to check primary key id
        finding = db.query(models.Finding).filter(models.Finding.id == uuid_obj).first()
        
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    updated_fields = []
    version_id = None
    
    # Update description if provided
    if update.description is not None:
        old_description = finding.description
        
        # Save old description to version history if it exists
        if old_description:
            history_entry = models.FindingHistory(
                finding_id=finding.id,
                change_type="description",
                old_value=old_description,
                new_value=update.description,
                comment="Description updated via AI analysis",
                change_metadata={"source": "ai_analysis", "timestamp": datetime.utcnow().isoformat()}
            )
            db.add(history_entry)
            db.flush()  # Get the ID
            version_id = str(history_entry.id)
        
        finding.description = update.description
        updated_fields.append("description")
    
    if updated_fields:
        db.commit()
        db.refresh(finding)
        logger.info(f"Updated finding {finding_id}: {updated_fields}")
    
    return FindingUpdateResponse(
        id=str(finding.finding_uuid),
        message=f"Successfully updated finding" if updated_fields else "No fields to update",
        updated_fields=updated_fields,
        version_id=version_id
    )


# =============================================================================
# Description Version History
# =============================================================================

class DescriptionVersionResponse(BaseModel):
    """A single description version."""
    id: str
    description: str
    created_at: datetime
    is_current: bool = False

class DescriptionVersionListResponse(BaseModel):
    """List of description versions."""
    finding_id: str
    current_description: Optional[str]
    versions: List[DescriptionVersionResponse]


@router.get("/{finding_id}/description-versions", response_model=DescriptionVersionListResponse)
def get_description_versions(finding_id: str, db: Session = Depends(get_db)):
    """Get all description versions for a finding."""
    try:
        uuid_obj = uuid.UUID(finding_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")

    finding = db.query(models.Finding).filter(models.Finding.finding_uuid == uuid_obj).first()
    if not finding:
        finding = db.query(models.Finding).filter(models.Finding.id == uuid_obj).first()
        
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Get all description history entries
    history = db.query(models.FindingHistory).filter(
        models.FindingHistory.finding_id == finding.id,
        models.FindingHistory.change_type == "description"
    ).order_by(models.FindingHistory.created_at.desc()).all()

    versions = []
    for h in history:
        # old_value contains the previous description that was replaced
        versions.append(DescriptionVersionResponse(
            id=str(h.id),
            description=h.old_value,
            created_at=h.created_at,
            is_current=False
        ))

    return DescriptionVersionListResponse(
        finding_id=str(finding.finding_uuid),
        current_description=finding.description,
        versions=versions
    )


class RestoreVersionRequest(BaseModel):
    """Request to restore a specific version."""
    version_id: str


@router.post("/{finding_id}/restore-description", response_model=FindingUpdateResponse)
def restore_description_version(finding_id: str, request: RestoreVersionRequest, db: Session = Depends(get_db)):
    """Restore a previous description version."""
    try:
        finding_uuid = uuid.UUID(finding_id)
        version_uuid = uuid.UUID(request.version_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")

    finding = db.query(models.Finding).filter(models.Finding.finding_uuid == finding_uuid).first()
    if not finding:
        finding = db.query(models.Finding).filter(models.Finding.id == finding_uuid).first()
        
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Get the version to restore
    version = db.query(models.FindingHistory).filter(
        models.FindingHistory.id == version_uuid,
        models.FindingHistory.finding_id == finding.id,
        models.FindingHistory.change_type == "description"
    ).first()

    if not version:
        raise HTTPException(status_code=404, detail="Version not found")

    # Save current description to history before restoring
    old_description = finding.description
    if old_description:
        history_entry = models.FindingHistory(
            finding_id=finding.id,
            change_type="description",
            old_value=old_description,
            new_value=version.old_value,
            comment="Description restored from version history",
            change_metadata={"source": "version_restore", "restored_version_id": str(version.id), "timestamp": datetime.utcnow().isoformat()}
        )
        db.add(history_entry)

    # Restore the old description
    finding.description = version.old_value
    db.commit()
    db.refresh(finding)
    
    logger.info(f"Restored description for finding {finding_id} from version {request.version_id}")

    return FindingUpdateResponse(
        id=str(finding.finding_uuid),
        message="Successfully restored description from version history",
        updated_fields=["description"],
        version_id=str(version.id)
    )


# =============================================================================
# Exception Management Models
# =============================================================================

class ExceptionRuleRequest(BaseModel):
    """Request to generate an exception rule for a finding."""
    finding_id: str
    scope: str  # "specific" or "global"
    reason: Optional[str] = None  # Optional reason for the exception

class ExceptionRuleResponse(BaseModel):
    """Response containing the generated exception rule."""
    scanner_name: str
    rule_type: str  # e.g., "allowlist", "exclude", "ignore"
    rule_content: str  # The actual rule (TOML, regex, etc.)
    instruction: str  # Where to apply this rule
    affected_count: int  # How many findings match this rule

class DeleteDryRunRequest(BaseModel):
    """Request for dry-run deletion analysis."""
    finding_id: str
    scope: str  # "specific" or "global"

class DeleteDryRunResponse(BaseModel):
    """Response showing what would be deleted."""
    count: int
    scanner_name: str
    file_path: Optional[str]
    sample_findings: List[dict]  # Sample of findings that would be deleted

class DeleteFindingsRequest(BaseModel):
    """Request to delete findings."""
    finding_id: str
    scope: str  # "specific" or "global"
    confirmed: bool = False  # Must be True to actually delete

class DeleteFindingsResponse(BaseModel):
    """Response after deletion."""
    deleted_count: int
    message: str


# =============================================================================
# Exception Rule Generation
# =============================================================================

def generate_gitleaks_rule(finding: models.Finding, scope: str) -> dict:
    """Generate a Gitleaks allowlist rule."""
    if scope == "specific":
        # Specific rule - match exact secret
        secret_value = finding.code_snippet or ""
        # Truncate and escape the secret for regex
        if len(secret_value) > 50:
            regex_pattern = f"{secret_value[:50]}.*"
        else:
            regex_pattern = f".*{secret_value}.*"

        rule_content = f'''[[rules.allowlist]]
description = "Exception for {finding.title}"
regexTarget = "match"
regexes = [
    "{regex_pattern}"
]
paths = [
    "{finding.file_path}"
]'''
    else:
        # Global rule - match file path
        rule_content = f'''[[rules.allowlist]]
description = "Global exception for {finding.file_path}"
paths = [
    "{finding.file_path}"
]'''

    return {
        "rule_type": "allowlist",
        "rule_content": rule_content,
        "instruction": "Add this rule to your gitleaks.toml configuration file in the [allowlist] section."
    }


def generate_trufflehog_rule(finding: models.Finding, scope: str) -> dict:
    """Generate a TruffleHog exclusion rule."""
    if scope == "specific":
        rule_content = f'''# Exception for {finding.title}
exclude:
  paths:
    - "{finding.file_path}"
  detectors:
    - "{finding.finding_type or 'generic'}"'''
    else:
        rule_content = f'''# Global exception for path
exclude:
  paths:
    - "{finding.file_path}"'''

    return {
        "rule_type": "exclude",
        "rule_content": rule_content,
        "instruction": "Add this to your TruffleHog configuration file or .trufflehog-ignore."
    }


def generate_semgrep_rule(finding: models.Finding, scope: str) -> dict:
    """Generate a Semgrep nosemgrep comment or ignore rule."""
    if scope == "specific":
        rule_content = f'''# Add this comment to the specific line in {finding.file_path}:
# nosemgrep: {finding.finding_type or 'rule-id'}

# Or add to .semgrepignore:
{finding.file_path}:{finding.line_start or 1}'''
    else:
        rule_content = f'''# Add to .semgrepignore file:
{finding.file_path}'''

    return {
        "rule_type": "ignore",
        "rule_content": rule_content,
        "instruction": "Add a nosemgrep comment to the code or add the path to .semgrepignore."
    }


def generate_generic_rule(finding: models.Finding, scope: str) -> dict:
    """Generate a generic exception rule for unknown scanners."""
    if scope == "specific":
        rule_content = f'''# Exception for specific finding
# Scanner: {finding.scanner_name}
# File: {finding.file_path}
# Line: {finding.line_start or 'N/A'}
# Title: {finding.title}

# Add to your scanner's ignore/allowlist configuration'''
    else:
        rule_content = f'''# Global exception for path
# Scanner: {finding.scanner_name}
# File: {finding.file_path}

# Add to your scanner's ignore/allowlist configuration'''

    return {
        "rule_type": "ignore",
        "rule_content": rule_content,
        "instruction": f"Consult the {finding.scanner_name} documentation for the appropriate ignore/allowlist format."
    }


@router.post("/exception/generate", response_model=ExceptionRuleResponse)
def generate_exception_rule(
    request: ExceptionRuleRequest,
    db: Session = Depends(get_db)
):
    """Generate an exception rule for a finding based on its scanner type."""
    # Get the finding
    try:
        uuid_obj = uuid.UUID(request.finding_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")

    finding = db.query(models.Finding).filter(models.Finding.finding_uuid == uuid_obj).first()
    if not finding:
        finding = db.query(models.Finding).filter(models.Finding.id == uuid_obj).first()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Validate scope
    if request.scope not in ["specific", "global"]:
        raise HTTPException(status_code=400, detail="Scope must be 'specific' or 'global'")

    scanner_name = (finding.scanner_name or "").lower()

    # Generate rule based on scanner type
    if "gitleaks" in scanner_name:
        rule_data = generate_gitleaks_rule(finding, request.scope)
    elif "trufflehog" in scanner_name:
        rule_data = generate_trufflehog_rule(finding, request.scope)
    elif "semgrep" in scanner_name:
        rule_data = generate_semgrep_rule(finding, request.scope)
    else:
        rule_data = generate_generic_rule(finding, request.scope)

    # Count affected findings
    if request.scope == "specific":
        affected_count = 1
    else:
        # Count all findings with same scanner and file path
        affected_count = db.query(models.Finding).filter(
            and_(
                models.Finding.scanner_name == finding.scanner_name,
                models.Finding.file_path == finding.file_path
            )
        ).count()

    return ExceptionRuleResponse(
        scanner_name=finding.scanner_name or "Unknown",
        rule_type=rule_data["rule_type"],
        rule_content=rule_data["rule_content"],
        instruction=rule_data["instruction"],
        affected_count=affected_count
    )


# =============================================================================
# Delete Findings with Dry-Run Verification
# =============================================================================

@router.post("/exception/delete/dry-run", response_model=DeleteDryRunResponse)
def delete_findings_dry_run(
    request: DeleteDryRunRequest,
    db: Session = Depends(get_db)
):
    """
    Perform a dry-run analysis to show how many findings would be deleted.
    This is a safety check before actual deletion.
    """
    # Get the finding
    try:
        uuid_obj = uuid.UUID(request.finding_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")

    finding = db.query(models.Finding).filter(models.Finding.finding_uuid == uuid_obj).first()
    if not finding:
        finding = db.query(models.Finding).filter(models.Finding.id == uuid_obj).first()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Validate scope
    if request.scope not in ["specific", "global"]:
        raise HTTPException(status_code=400, detail="Scope must be 'specific' or 'global'")

    if request.scope == "specific":
        # Only this specific finding
        count = 1
        sample_findings = [{
            "id": str(finding.finding_uuid),
            "title": finding.title,
            "file_path": finding.file_path,
            "scanner_name": finding.scanner_name
        }]
    else:
        # Global scope - match scanner AND file path for safety
        query = db.query(models.Finding).filter(
            and_(
                models.Finding.scanner_name == finding.scanner_name,
                models.Finding.file_path == finding.file_path
            )
        )
        count = query.count()

        # Get sample of findings (up to 5)
        sample = query.limit(5).all()
        sample_findings = [{
            "id": str(f.finding_uuid),
            "title": f.title,
            "file_path": f.file_path,
            "scanner_name": f.scanner_name
        } for f in sample]

    return DeleteDryRunResponse(
        count=count,
        scanner_name=finding.scanner_name or "Unknown",
        file_path=finding.file_path,
        sample_findings=sample_findings
    )


@router.post("/exception/delete", response_model=DeleteFindingsResponse)
def delete_findings(
    request: DeleteFindingsRequest,
    db: Session = Depends(get_db)
):
    """
    Delete findings based on scope. Requires confirmed=True for safety.

    - specific: Delete only the specified finding
    - global: Delete all findings with same scanner AND file path
    """
    if not request.confirmed:
        raise HTTPException(
            status_code=400,
            detail="Deletion not confirmed. Set confirmed=True after reviewing the dry-run results."
        )

    # Get the finding
    try:
        uuid_obj = uuid.UUID(request.finding_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")

    finding = db.query(models.Finding).filter(models.Finding.finding_uuid == uuid_obj).first()
    if not finding:
        finding = db.query(models.Finding).filter(models.Finding.id == uuid_obj).first()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Validate scope
    if request.scope not in ["specific", "global"]:
        raise HTTPException(status_code=400, detail="Scope must be 'specific' or 'global'")

    try:
        if request.scope == "specific":
            # Delete only this specific finding
            # First delete related remediations
            db.query(models.Remediation).filter(models.Remediation.finding_id == finding.id).delete()
            db.delete(finding)
            deleted_count = 1
        else:
            # Global scope - match scanner AND file path for safety
            # Get all matching findings
            matching_findings = db.query(models.Finding).filter(
                and_(
                    models.Finding.scanner_name == finding.scanner_name,
                    models.Finding.file_path == finding.file_path
                )
            ).all()

            deleted_count = len(matching_findings)

            # Delete remediations for all matching findings
            for f in matching_findings:
                db.query(models.Remediation).filter(models.Remediation.finding_id == f.id).delete()

            # Delete the findings
            db.query(models.Finding).filter(
                and_(
                    models.Finding.scanner_name == finding.scanner_name,
                    models.Finding.file_path == finding.file_path
                )
            ).delete()

        db.commit()
        logger.info(f"Deleted {deleted_count} finding(s) with scope '{request.scope}'")

        return DeleteFindingsResponse(
            deleted_count=deleted_count,
            message=f"Successfully deleted {deleted_count} finding(s)."
        )

    except Exception as e:
        db.rollback()
        logger.error(f"Error deleting findings: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to delete findings: {str(e)}")


# =============================================================================
# Investigation Status & Journal API
# =============================================================================

class InvestigationStatusUpdate(BaseModel):
    """Request to update investigation status."""
    status: str  # 'triage', 'incident_response', 'resolved', or null to clear

class JournalEntryRequest(BaseModel):
    """Request to create a journal entry."""
    entry_text: str
    entry_type: Optional[str] = 'note'  # 'note', 'status_change', 'ai_response', 'communication'
    author_name: Optional[str] = 'Analyst'
    is_ai_generated: Optional[bool] = False
    ai_prompt: Optional[str] = None

class JournalEntryResponse(BaseModel):
    """A single journal entry."""
    id: str
    entry_text: str
    entry_type: str
    author_name: str
    is_ai_generated: bool
    ai_prompt: Optional[str]
    created_at: datetime

    model_config = {"from_attributes": True}

class InvestigationStatusResponse(BaseModel):
    """Response with investigation status and journal."""
    finding_id: str
    investigation_status: Optional[str]
    investigation_started_at: Optional[datetime]
    investigation_resolved_at: Optional[datetime]
    journal_entries: List[JournalEntryResponse]

class AskJournalAIRequest(BaseModel):
    """Request to ask AI a question about the finding in journal context."""
    question: str
    author_name: Optional[str] = 'Analyst'

class JournalEntryUpdateRequest(BaseModel):
    """Request to update a journal entry."""
    entry_text: Optional[str] = None
    entry_type: Optional[str] = None  # 'note', 'status_change', 'ai_response', 'communication'
    author_name: Optional[str] = None


@router.get("/{finding_id}/investigation", response_model=InvestigationStatusResponse)
def get_investigation_status(finding_id: str, db: Session = Depends(get_db)):
    """Get investigation status and journal entries for a finding."""
    try:
        uuid_obj = uuid.UUID(finding_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")

    finding = db.query(models.Finding).filter(models.Finding.finding_uuid == uuid_obj).first()
    if not finding:
        finding = db.query(models.Finding).filter(models.Finding.id == uuid_obj).first()
        
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Get journal entries
    journal_entries = db.query(models.JournalEntry).filter(
        models.JournalEntry.finding_id == finding.id
    ).order_by(models.JournalEntry.created_at.desc()).all()

    return InvestigationStatusResponse(
        finding_id=str(finding.finding_uuid),
        investigation_status=finding.investigation_status,
        investigation_started_at=finding.investigation_started_at,
        investigation_resolved_at=finding.investigation_resolved_at,
        journal_entries=[JournalEntryResponse(
            id=str(entry.id),
            entry_text=entry.entry_text,
            entry_type=entry.entry_type or 'note',
            author_name=entry.author_name or 'Analyst',
            is_ai_generated=entry.is_ai_generated or False,
            ai_prompt=entry.ai_prompt,
            created_at=entry.created_at
        ) for entry in journal_entries]
    )


@router.patch("/{finding_id}/investigation/status")
def update_investigation_status(finding_id: str, update: InvestigationStatusUpdate, db: Session = Depends(get_db)):
    """Update investigation status for a finding."""
    try:
        uuid_obj = uuid.UUID(finding_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")

    finding = db.query(models.Finding).filter(models.Finding.finding_uuid == uuid_obj).first()
    if not finding:
        finding = db.query(models.Finding).filter(models.Finding.id == uuid_obj).first()
        
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Validate status
    valid_statuses = ['triage', 'incident_response', 'resolved', None, '']
    if update.status and update.status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: triage, incident_response, resolved")

    old_status = finding.investigation_status
    new_status = update.status if update.status else None

    # Update timestamps based on status changes
    if new_status and not old_status:
        # Starting investigation
        finding.investigation_started_at = datetime.utcnow()
    
    if new_status == 'resolved' and old_status != 'resolved':
        finding.investigation_resolved_at = datetime.utcnow()
    elif new_status != 'resolved':
        finding.investigation_resolved_at = None

    finding.investigation_status = new_status
    
    # Create a status change journal entry
    if old_status != new_status:
        status_entry = models.JournalEntry(
            finding_id=finding.id,
            entry_text=f"Status changed from **{old_status or 'None'}** to **{new_status or 'None'}**",
            entry_type='status_change',
            author_name='System',
            is_ai_generated=False
        )
        db.add(status_entry)

    db.commit()
    db.refresh(finding)

    return {
        "finding_id": str(finding.finding_uuid),
        "investigation_status": finding.investigation_status,
        "investigation_started_at": finding.investigation_started_at,
        "investigation_resolved_at": finding.investigation_resolved_at,
        "message": f"Status updated to {new_status or 'None'}"
    }


@router.post("/{finding_id}/journal", response_model=JournalEntryResponse)
def create_journal_entry(finding_id: str, entry: JournalEntryRequest, db: Session = Depends(get_db)):
    """Create a new journal entry for a finding."""
    try:
        uuid_obj = uuid.UUID(finding_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")

    finding = db.query(models.Finding).filter(models.Finding.finding_uuid == uuid_obj).first()
    if not finding:
        finding = db.query(models.Finding).filter(models.Finding.id == uuid_obj).first()
        
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    journal_entry = models.JournalEntry(
        finding_id=finding.id,
        entry_text=entry.entry_text,
        entry_type=entry.entry_type or 'note',
        author_name=entry.author_name or 'Analyst',
        is_ai_generated=entry.is_ai_generated or False,
        ai_prompt=entry.ai_prompt
    )
    db.add(journal_entry)
    db.commit()
    db.refresh(journal_entry)

    return JournalEntryResponse(
        id=str(journal_entry.id),
        entry_text=journal_entry.entry_text,
        entry_type=journal_entry.entry_type or 'note',
        author_name=journal_entry.author_name or 'Analyst',
        is_ai_generated=journal_entry.is_ai_generated or False,
        ai_prompt=journal_entry.ai_prompt,
        created_at=journal_entry.created_at
    )


@router.post("/{finding_id}/journal/ask-ai", response_model=JournalEntryResponse)
async def ask_journal_ai(finding_id: str, request: AskJournalAIRequest, db: Session = Depends(get_db)):
    """Ask AI a question in the context of the journal and get an AI response."""
    from ..config import settings
    
    try:
        uuid_obj = uuid.UUID(finding_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")

    finding = db.query(models.Finding).filter(models.Finding.finding_uuid == uuid_obj).first()
    if not finding:
        finding = db.query(models.Finding).filter(models.Finding.id == uuid_obj).first()
        
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Get recent journal entries for context
    recent_entries = db.query(models.JournalEntry).filter(
        models.JournalEntry.finding_id == finding.id
    ).order_by(models.JournalEntry.created_at.desc()).limit(10).all()

    # Build context for AI
    journal_context = "\n".join([
        f"[{e.created_at.strftime('%Y-%m-%d %H:%M')}] {e.author_name}: {e.entry_text}"
        for e in reversed(recent_entries)
    ])

    # Prepare the AI prompt
    system_prompt = f"""You are a security analyst assistant helping investigate a security finding.

**Finding Information:**
- Title: {finding.title}
- Severity: {finding.severity}
- Scanner: {finding.scanner_name}
- File: {finding.file_path}
- Description: {finding.description or 'No description'}
- Code Snippet: {finding.code_snippet or 'No code snippet'}

**Recent Journal Entries:**
{journal_context if journal_context else 'No previous journal entries'}

Please provide helpful, actionable advice for the analyst's question. Be concise but thorough."""

    # Call AI provider
    ai_response = None
    try:
        if settings.OPENAI_API_KEY:
            import openai
            client = openai.OpenAI(api_key=settings.OPENAI_API_KEY)
            response = client.chat.completions.create(
                model=settings.AI_MODEL or "gpt-4o-mini",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": request.question}
                ],
                max_tokens=1000
            )
            ai_response = response.choices[0].message.content
        elif settings.ANTHROPIC_API_KEY:
            import anthropic
            client = anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)
            response = client.messages.create(
                model=settings.AI_MODEL or "claude-3-haiku-20240307",
                max_tokens=1000,
                system=system_prompt,
                messages=[{"role": "user", "content": request.question}]
            )
            ai_response = response.content[0].text
        else:
            ai_response = "AI assistant is not configured. Please set up OpenAI or Anthropic API keys."
    except Exception as e:
        logger.error(f"AI request failed: {e}")
        ai_response = f"Failed to get AI response: {str(e)}"

    # Save the user's question as a journal entry
    user_entry = models.JournalEntry(
        finding_id=finding.id,
        entry_text=request.question,
        entry_type='note',
        author_name=request.author_name or 'Analyst',
        is_ai_generated=False
    )
    db.add(user_entry)
    
    # Save the AI response as a journal entry
    ai_entry = models.JournalEntry(
        finding_id=finding.id,
        entry_text=ai_response,
        entry_type='ai_response',
        author_name='AI Assistant',
        is_ai_generated=True,
        ai_prompt=request.question
    )
    db.add(ai_entry)
    db.commit()
    db.refresh(ai_entry)

    return JournalEntryResponse(
        id=str(ai_entry.id),
        entry_text=ai_entry.entry_text,
        entry_type=ai_entry.entry_type or 'ai_response',
        author_name=ai_entry.author_name or 'AI Assistant',
        is_ai_generated=True,
        ai_prompt=ai_entry.ai_prompt,
        created_at=ai_entry.created_at
    )


@router.get("/{finding_id}/journal/{entry_id}", response_model=JournalEntryResponse)
def get_journal_entry(finding_id: str, entry_id: str, db: Session = Depends(get_db)):
    """Get a specific journal entry for a finding."""
    try:
        finding_uuid = uuid.UUID(finding_id)
        entry_uuid = uuid.UUID(entry_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")

    # Find the finding
    finding = db.query(models.Finding).filter(models.Finding.finding_uuid == finding_uuid).first()
    if not finding:
        finding = db.query(models.Finding).filter(models.Finding.id == finding_uuid).first()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Find the journal entry
    journal_entry = db.query(models.JournalEntry).filter(
        models.JournalEntry.id == entry_uuid,
        models.JournalEntry.finding_id == finding.id
    ).first()

    if not journal_entry:
        raise HTTPException(status_code=404, detail="Journal entry not found")

    return JournalEntryResponse(
        id=str(journal_entry.id),
        entry_text=journal_entry.entry_text,
        entry_type=journal_entry.entry_type or 'note',
        author_name=journal_entry.author_name or 'Analyst',
        is_ai_generated=journal_entry.is_ai_generated or False,
        ai_prompt=journal_entry.ai_prompt,
        created_at=journal_entry.created_at
    )


@router.put("/{finding_id}/journal/{entry_id}", response_model=JournalEntryResponse)
def update_journal_entry(
    finding_id: str,
    entry_id: str,
    update: JournalEntryUpdateRequest,
    db: Session = Depends(get_db)
):
    """Update a journal entry for a finding."""
    try:
        finding_uuid = uuid.UUID(finding_id)
        entry_uuid = uuid.UUID(entry_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")

    # Find the finding
    finding = db.query(models.Finding).filter(models.Finding.finding_uuid == finding_uuid).first()
    if not finding:
        finding = db.query(models.Finding).filter(models.Finding.id == finding_uuid).first()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Find the journal entry
    journal_entry = db.query(models.JournalEntry).filter(
        models.JournalEntry.id == entry_uuid,
        models.JournalEntry.finding_id == finding.id
    ).first()

    if not journal_entry:
        raise HTTPException(status_code=404, detail="Journal entry not found")

    # Prevent editing system-generated status change entries
    if journal_entry.entry_type == 'status_change' and journal_entry.author_name == 'System':
        raise HTTPException(
            status_code=403,
            detail="System-generated status change entries cannot be modified"
        )

    # Update fields if provided
    if update.entry_text is not None:
        journal_entry.entry_text = update.entry_text
    if update.entry_type is not None:
        valid_types = ['note', 'status_change', 'ai_response', 'communication']
        if update.entry_type not in valid_types:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid entry_type. Must be one of: {', '.join(valid_types)}"
            )
        journal_entry.entry_type = update.entry_type
    if update.author_name is not None:
        journal_entry.author_name = update.author_name

    db.commit()
    db.refresh(journal_entry)

    return JournalEntryResponse(
        id=str(journal_entry.id),
        entry_text=journal_entry.entry_text,
        entry_type=journal_entry.entry_type or 'note',
        author_name=journal_entry.author_name or 'Analyst',
        is_ai_generated=journal_entry.is_ai_generated or False,
        ai_prompt=journal_entry.ai_prompt,
        created_at=journal_entry.created_at
    )


@router.delete("/{finding_id}/journal/{entry_id}")
def delete_journal_entry(finding_id: str, entry_id: str, db: Session = Depends(get_db)):
    """Delete a journal entry for a finding."""
    try:
        finding_uuid = uuid.UUID(finding_id)
        entry_uuid = uuid.UUID(entry_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")

    # Find the finding
    finding = db.query(models.Finding).filter(models.Finding.finding_uuid == finding_uuid).first()
    if not finding:
        finding = db.query(models.Finding).filter(models.Finding.id == finding_uuid).first()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Find the journal entry
    journal_entry = db.query(models.JournalEntry).filter(
        models.JournalEntry.id == entry_uuid,
        models.JournalEntry.finding_id == finding.id
    ).first()

    if not journal_entry:
        raise HTTPException(status_code=404, detail="Journal entry not found")

    # Prevent deleting system-generated status change entries
    if journal_entry.entry_type == 'status_change' and journal_entry.author_name == 'System':
        raise HTTPException(
            status_code=403,
            detail="System-generated status change entries cannot be deleted"
        )

    db.delete(journal_entry)
    db.commit()

    return {
        "status": "success",
        "message": "Journal entry deleted",
        "deleted_id": entry_id
    }
