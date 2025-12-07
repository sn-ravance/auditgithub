from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import List, Dict, Any, Optional
from ..database import get_db
from .. import models
from .. import models
import uuid
from pydantic import BaseModel
from datetime import datetime
import os

router = APIRouter(
    prefix="/projects",
    tags=["projects"]
)

@router.get("/")
async def get_projects(db: Session = Depends(get_db)):
    """Get a list of all projects with summary stats."""
    projects = db.query(models.Repository).all()

    results = []
    for p in projects:
        open_findings = db.query(models.Finding).filter(
            models.Finding.repository_id == p.id,
            models.Finding.status == 'open'
        ).count()

        # Get the most recent commit date from contributors (fallback)
        last_commit = db.query(func.max(models.Contributor.last_commit_at)).filter(
            models.Contributor.repository_id == p.id
        ).scalar()

        # Get highest severity from SAST findings
        severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
        sast_findings = db.query(models.Finding).filter(
            models.Finding.repository_id == p.id,
            models.Finding.finding_type == 'sast',
            models.Finding.status == 'open'
        ).all()

        max_severity = None
        max_severity_value = 0
        for finding in sast_findings:
            severity = finding.severity.lower() if finding.severity else 'low'
            severity_value = severity_order.get(severity, 0)
            if severity_value > max_severity_value:
                max_severity_value = severity_value
                max_severity = finding.severity

        results.append({
            "id": str(p.id),
            "name": p.name,
            "description": p.description,
            "language": p.language or "Unknown",
            "default_branch": p.default_branch or "main",
            "last_scanned_at": p.last_scanned_at,
            # Use pushed_at from GitHub API, fallback to contributor data
            "last_commit_at": p.pushed_at or last_commit,
            "pushed_at": p.pushed_at,
            "visibility": p.visibility,
            "is_archived": p.is_archived,
            "is_private": p.is_private,
            "max_severity": max_severity,
            "stats": {
                "open_findings": open_findings,
                "stars": p.stargazers_count or 0,
                "forks": p.forks_count or 0,
            }
        })

    return results

@router.get("/{project_id}")
async def get_project_details(project_id: str, db: Session = Depends(get_db)):
    """Get basic details for a specific project."""
    try:
        # Try to parse UUID
        p_uuid = uuid.UUID(project_id)
        project = db.query(models.Repository).filter(models.Repository.id == p_uuid).first()
    except ValueError:
        # Fallback to name search if not a UUID (for convenience)
        project = db.query(models.Repository).filter(models.Repository.name == project_id).first()

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Calculate aggregate stats
    open_findings_count = db.query(models.Finding).filter(
        models.Finding.repository_id == project.id,
        models.Finding.status == 'open'
    ).count()
    
    return {
        "id": str(project.id),
        "name": project.name,
        "full_name": project.full_name,
        "description": project.description,
        "url": project.url,
        "language": project.language or "Unknown",
        "default_branch": project.default_branch or "main",
        "last_scanned_at": project.last_scanned_at,
        # GitHub API metadata
        "pushed_at": project.pushed_at,
        "github_created_at": project.github_created_at,
        "github_updated_at": project.github_updated_at,
        "visibility": project.visibility,
        "is_archived": project.is_archived,
        "is_private": project.is_private,
        "is_fork": project.is_fork,
        "topics": project.topics or [],
        "license_name": project.license_name,
        "has_wiki": project.has_wiki,
        "has_pages": project.has_pages,
        "has_discussions": project.has_discussions,
        "stats": {
            "open_findings": open_findings_count,
            "stars": project.stargazers_count or 0,
            "forks": project.forks_count or 0,
            "watchers": project.watchers_count or 0,
            "open_issues": project.open_issues_count or 0,
            "size_kb": project.size_kb or 0,
        }
    }

@router.get("/{project_id}/secrets")
async def get_project_secrets(project_id: str, db: Session = Depends(get_db)):
    """Get secrets findings for a project."""
    try:
        p_uuid = uuid.UUID(project_id)
        project = db.query(models.Repository).filter(models.Repository.id == p_uuid).first()
    except ValueError:
        project = db.query(models.Repository).filter(models.Repository.name == project_id).first()
        
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    findings = db.query(models.Finding).filter(
        models.Finding.repository_id == project.id,
        models.Finding.finding_type == 'secret',
        models.Finding.status == 'open'
    ).all()

    return [{
        "id": str(f.finding_uuid),
        "title": f.title,
        "severity": f.severity,
        "file_path": f.file_path,
        "line": f.line_start,
        "description": f.description,
        "created_at": f.created_at
    } for f in findings]

@router.get("/{project_id}/sast")
async def get_project_sast(project_id: str, db: Session = Depends(get_db)):
    """Get SAST (Semgrep/CodeQL) findings for a project."""
    try:
        p_uuid = uuid.UUID(project_id)
        project = db.query(models.Repository).filter(models.Repository.id == p_uuid).first()
    except ValueError:
        project = db.query(models.Repository).filter(models.Repository.name == project_id).first()

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    findings = db.query(models.Finding).filter(
        models.Finding.repository_id == project.id,
        models.Finding.finding_type == 'sast',
        models.Finding.status == 'open'
    ).all()

    return [{
        "id": str(f.finding_uuid),
        "title": f.title,
        "severity": f.severity,
        "file_path": f.file_path,
        "line": f.line_start,
        "description": f.description,
        "created_at": f.created_at
    } for f in findings]

class FileWithSeverity(BaseModel):
    """File entry with security severity data."""
    path: str
    severity: Optional[str]
    findings_count: int = 0


class ContributorSummary(BaseModel):
    """Summary for table display."""
    id: str
    name: str
    email: Optional[str]
    github_username: Optional[str]
    commits: int
    commit_percentage: Optional[float]
    last_commit_at: Optional[datetime]
    languages: List[str]
    files_count: int
    folders_count: int
    risk_score: int
    highest_severity: Optional[str]

    model_config = {"from_attributes": True}


class ContributorDetail(BaseModel):
    """Full contributor details for modal display."""
    id: str
    name: str
    email: Optional[str]
    github_username: Optional[str]
    commits: int
    commit_percentage: Optional[float]
    last_commit_at: Optional[datetime]
    languages: List[str]
    files_contributed: List[FileWithSeverity]
    folders_contributed: List[str]
    risk_score: int
    ai_summary: Optional[str]
    # Computed stats for modal
    critical_files_count: int = 0
    high_files_count: int = 0
    medium_files_count: int = 0
    low_files_count: int = 0

    model_config = {"from_attributes": True}


class ContributorsResponse(BaseModel):
    """Response for contributors list endpoint."""
    total_contributors: int
    total_commits: int
    bus_factor: int
    team_ai_summary: Optional[str]
    contributors: List[ContributorSummary]


# Keep old response model for backward compatibility
class ContributorResponse(BaseModel):
    id: str
    name: str
    email: Optional[str]
    commits: int
    last_commit_at: Optional[datetime]
    languages: List[str]
    risk_score: int

    model_config = {"from_attributes": True}


@router.get("/{project_id}/contributors", response_model=ContributorsResponse)
def get_project_contributors(
    project_id: str,
    db: Session = Depends(get_db),
    limit: int = 100
):
    """Get all contributors with summary data for table display."""
    try:
        repo_uuid = uuid.UUID(project_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid project ID format")

    repo = db.query(models.Repository).filter(models.Repository.id == repo_uuid).first()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")

    contributors = db.query(models.Contributor).filter(
        models.Contributor.repository_id == repo_uuid
    ).order_by(models.Contributor.commits.desc()).limit(limit).all()

    total_commits = sum(c.commits for c in contributors)

    # Calculate bus factor (minimum contributors needed for 50% of commits)
    bus_factor = 0
    cumulative = 0
    threshold = total_commits * 0.5
    for i, c in enumerate(contributors, 1):
        cumulative += c.commits
        if cumulative >= threshold:
            bus_factor = i
            break

    # Build summary responses
    summaries = []
    for c in contributors:
        files = c.files_contributed or []

        # Get highest severity
        severities = [f.get('severity') for f in files if f.get('severity')]
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        highest = None
        if severities:
            highest = min(severities, key=lambda s: severity_order.get(s, 99))

        summaries.append(ContributorSummary(
            id=str(c.id),
            name=c.name,
            email=c.email,
            github_username=c.github_username,
            commits=c.commits,
            commit_percentage=float(c.commit_percentage) if c.commit_percentage else None,
            last_commit_at=c.last_commit_at,
            languages=c.languages or [],
            files_count=len(files),
            folders_count=len(c.folders_contributed or []),
            risk_score=c.risk_score or 0,
            highest_severity=highest
        ))

    return ContributorsResponse(
        total_contributors=len(contributors),
        total_commits=total_commits,
        bus_factor=bus_factor,
        team_ai_summary=None,  # Can be populated from repo-level AI analysis
        contributors=summaries
    )


@router.get("/{project_id}/contributors/{contributor_id}", response_model=ContributorDetail)
def get_contributor_detail(
    project_id: str,
    contributor_id: str,
    db: Session = Depends(get_db)
):
    """Get full contributor details for modal display."""
    try:
        repo_uuid = uuid.UUID(project_id)
        contrib_uuid = uuid.UUID(contributor_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid ID format")

    contributor = db.query(models.Contributor).filter(
        models.Contributor.id == contrib_uuid,
        models.Contributor.repository_id == repo_uuid
    ).first()

    if not contributor:
        raise HTTPException(status_code=404, detail="Contributor not found")

    files = contributor.files_contributed or []

    # Count files by severity
    critical_count = len([f for f in files if f.get('severity') == 'critical'])
    high_count = len([f for f in files if f.get('severity') == 'high'])
    medium_count = len([f for f in files if f.get('severity') == 'medium'])
    low_count = len([f for f in files if f.get('severity') == 'low'])

    return ContributorDetail(
        id=str(contributor.id),
        name=contributor.name,
        email=contributor.email,
        github_username=contributor.github_username,
        commits=contributor.commits,
        commit_percentage=float(contributor.commit_percentage) if contributor.commit_percentage else None,
        last_commit_at=contributor.last_commit_at,
        languages=contributor.languages or [],
        files_contributed=[FileWithSeverity(**f) for f in files],
        folders_contributed=contributor.folders_contributed or [],
        risk_score=contributor.risk_score or 0,
        ai_summary=contributor.ai_summary,
        critical_files_count=critical_count,
        high_files_count=high_count,
        medium_files_count=medium_count,
        low_files_count=low_count
    )

class LanguageStatResponse(BaseModel):
    name: str
    files: int
    lines: int
    blanks: int
    comments: int
    findings: Dict[str, int] # severity -> count

    model_config = {"from_attributes": True}

@router.get("/{project_id}/languages", response_model=List[LanguageStatResponse])
def get_project_languages(project_id: str, db: Session = Depends(get_db)):
    """Get language stats and findings for a project."""
    try:
        uuid_obj = uuid.UUID(project_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")

    repo = db.query(models.Repository).filter(models.Repository.id == uuid_obj).first()
    if not repo:
        raise HTTPException(status_code=404, detail="Project not found")

    # Get all findings for this repo
    findings = db.query(models.Finding).filter(
        models.Finding.repository_id == repo.id,
        models.Finding.status == 'open'
    ).all()

    # Map extensions to languages (simplified map for now)
    # In a real app, we might use a library or DB table for this
    ext_map = {
        '.py': 'Python', '.js': 'JavaScript', '.ts': 'TypeScript', '.tsx': 'TypeScript',
        '.jsx': 'JavaScript', '.go': 'Go', '.java': 'Java', '.c': 'C', '.cpp': 'C++',
        '.rb': 'Ruby', '.php': 'PHP', '.rs': 'Rust', '.html': 'HTML', '.css': 'CSS',
        '.sh': 'Shell', '.yml': 'YAML', '.yaml': 'YAML', '.json': 'JSON', '.md': 'Markdown',
        '.sql': 'SQL', '.dockerfile': 'Docker', '.tf': 'HCL'
    }

    # Aggregate findings by language
    findings_by_lang = {} # lang -> {severity -> count}
    
    for f in findings:
        ext = os.path.splitext(f.file_path)[1].lower() if f.file_path else ""
        lang = ext_map.get(ext, "Other")
        
        if lang not in findings_by_lang:
            findings_by_lang[lang] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            
        severity = f.severity.lower()
        if severity in findings_by_lang[lang]:
            findings_by_lang[lang][severity] += 1

    # Combine with stored language stats
    results = []
    for stat in repo.languages:
        f_stats = findings_by_lang.get(stat.name, {"critical": 0, "high": 0, "medium": 0, "low": 0})
        results.append(LanguageStatResponse(
            name=stat.name,
            files=stat.files,
            lines=stat.lines,
            blanks=stat.blanks,
            comments=stat.comments,
            findings=f_stats
        ))
        
    # Sort by lines of code desc
    results.sort(key=lambda x: x.lines, reverse=True)
    
    return results

class DependencyResponse(BaseModel):
    id: str
    name: str
    version: str
    type: str
    package_manager: str
    license: str
    locations: List[str]
    source: Optional[str]
    
    # Enriched fields
    vulnerability_count: int = 0
    max_severity: str = "Safe"
    ai_analysis: Optional[Dict[str, Any]] = None

    model_config = {"from_attributes": True}

@router.get("/{project_id}/dependencies", response_model=List[DependencyResponse])
def get_project_dependencies(project_id: str, db: Session = Depends(get_db)):
    """Get dependencies (SBOM) for a project, enriched with vulnerability data."""
    try:
        uuid_obj = uuid.UUID(project_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")

    repo = db.query(models.Repository).filter(models.Repository.id == uuid_obj).first()
    if not repo:
        raise HTTPException(status_code=404, detail="Project not found")

    # 1. Fetch all dependencies
    dependencies = repo.dependencies
    
    # 2. Fetch all findings for this repo that are related to dependencies
    # We assume findings with package_name are dependency findings
    findings = db.query(models.Finding).filter(
        models.Finding.repository_id == repo.id,
        models.Finding.package_name.isnot(None)
    ).all()
    
    # Map findings to dependencies (name + version)
    findings_map = {} # (name, version) -> [findings]
    for f in findings:
        key = (f.package_name, f.package_version)
        if key not in findings_map:
            findings_map[key] = []
        findings_map[key].append(f)
        
    # 3. Fetch all component analyses
    # We can't easily filter by list of tuples in SQL without complex query, 
    # so we might fetch all relevant ones or just fetch individually if list is small.
    # For now, let's fetch all analyses that match any dependency name in this repo
    dep_names = [d.name for d in dependencies]
    analyses = db.query(models.ComponentAnalysis).filter(
        models.ComponentAnalysis.package_name.in_(dep_names)
    ).all()
    
    analysis_map = {} # (name, version, manager) -> analysis
    for a in analyses:
        # Normalize manager if needed, but for now assume exact match
        key = (a.package_name, a.version, a.package_manager)
        analysis_map[key] = a

    results = []
    for d in dependencies:
        # Find matching findings
        # Try exact match first
        related_findings = findings_map.get((d.name, d.version), [])
        
        # Calculate max severity
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "safe": -1}
        max_sev = "Safe"
        max_score = -1
        
        for f in related_findings:
            s = f.severity.lower() if f.severity else "low"
            score = severity_order.get(s, 0)
            if score > max_score:
                max_score = score
                max_sev = f.severity
        
        if not related_findings and max_score == -1:
             max_sev = "Safe"

        # Find matching analysis
        # We need to be careful with package_manager names matching
        # Syft might say 'npm', we store 'npm'.
        analysis = analysis_map.get((d.name, d.version, d.package_manager))
        analysis_data = None
        if analysis:
            analysis_data = {
                "vulnerability_summary": analysis.vulnerability_summary,
                "analysis_text": analysis.analysis_text,
                "severity": analysis.severity,
                "exploitability": analysis.exploitability,
                "fixed_version": analysis.fixed_version,
                "source": "cache"
            }

        results.append(DependencyResponse(
            id=str(d.id),
            name=d.name,
            version=d.version or "Unknown",
            type=d.type or "Unknown",
            package_manager=d.package_manager or "Unknown",
            license=d.license or "Unknown",
            locations=d.locations if d.locations else [],
            source=d.source,
            vulnerability_count=len(related_findings),
            max_severity=max_sev,
            ai_analysis=analysis_data
        ))
        
    return results

@router.get("/{project_id}/terraform")
async def get_project_terraform(project_id: str, db: Session = Depends(get_db)):
    """Get Terraform/IaC findings for a project."""
    try:
        p_uuid = uuid.UUID(project_id)
        project = db.query(models.Repository).filter(models.Repository.id == p_uuid).first()
    except ValueError:
        project = db.query(models.Repository).filter(models.Repository.name == project_id).first()

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    findings = db.query(models.Finding).filter(
        models.Finding.repository_id == project.id,
        models.Finding.finding_type == 'iac',
        models.Finding.status == 'open'
    ).all()

    return [{
        "id": str(f.finding_uuid),
        "title": f.title,
        "severity": f.severity,
        "file_path": f.file_path,
        "line": f.line_start,
        "description": f.description,
        "created_at": f.created_at
    } for f in findings]

@router.get("/{project_id}/oss")
async def get_project_oss(project_id: str, db: Session = Depends(get_db)):
    """Get OSS/Dependency findings for a project."""
    try:
        p_uuid = uuid.UUID(project_id)
        project = db.query(models.Repository).filter(models.Repository.id == p_uuid).first()
    except ValueError:
        project = db.query(models.Repository).filter(models.Repository.name == project_id).first()

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    findings = db.query(models.Finding).filter(
        models.Finding.repository_id == project.id,
        models.Finding.finding_type == 'oss',
        models.Finding.status == 'open'
    ).all()

    return [{
        "id": str(f.finding_uuid),
        "title": f.title,
        "severity": f.severity,
        "file_path": f.file_path,
        "line": f.line_start,
        "description": f.description,
        "created_at": f.created_at
    } for f in findings]

@router.get("/{project_id}/runs")
async def get_project_runs(project_id: str, db: Session = Depends(get_db)):
    """Get scan runs for a project."""
    try:
        p_uuid = uuid.UUID(project_id)
        project = db.query(models.Repository).filter(models.Repository.id == p_uuid).first()
    except ValueError:
        project = db.query(models.Repository).filter(models.Repository.name == project_id).first()

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    runs = db.query(models.ScanRun).filter(
        models.ScanRun.repository_id == project.id
    ).order_by(models.ScanRun.created_at.desc()).limit(50).all()

    return [{
        "id": str(r.id),
        "scan_type": r.scan_type,
        "status": r.status,
        "findings_count": r.findings_count,
        "created_at": r.created_at,
        "completed_at": r.completed_at,
        "duration_seconds": r.duration_seconds
    } for r in runs]
