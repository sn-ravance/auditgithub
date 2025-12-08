from sqlalchemy import Column, String, Integer, Boolean, DateTime, ForeignKey, Text, JSON, Numeric, Sequence, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func, text
from .database import Base

class Repository(Base):
    __tablename__ = "repositories"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    api_id = Column(Integer, Sequence('repositories_api_id_seq'), unique=True)
    name = Column(String, unique=True, nullable=False)
    full_name = Column(String)
    url = Column(Text)
    description = Column(Text)
    default_branch = Column(String)
    language = Column(String)
    owner_type = Column(String)
    owner_id = Column(String)
    business_criticality = Column(String)
    last_scanned_at = Column(DateTime)

    # GitHub API metadata
    pushed_at = Column(DateTime)  # Last push to any branch (from GitHub API)
    github_created_at = Column(DateTime)  # Repo creation date on GitHub
    github_updated_at = Column(DateTime)  # Last metadata update on GitHub
    stargazers_count = Column(Integer, default=0)
    watchers_count = Column(Integer, default=0)
    forks_count = Column(Integer, default=0)
    open_issues_count = Column(Integer, default=0)
    size_kb = Column(Integer, default=0)  # Repository size in KB
    is_fork = Column(Boolean, default=False)
    is_archived = Column(Boolean, default=False)
    is_disabled = Column(Boolean, default=False)
    is_private = Column(Boolean, default=True)
    visibility = Column(String)  # public, private, internal
    topics = Column(JSONB)  # Array of topic tags
    license_name = Column(String)  # e.g., "MIT", "Apache-2.0"
    has_wiki = Column(Boolean, default=False)
    has_pages = Column(Boolean, default=False)
    has_discussions = Column(Boolean, default=False)

    # Self-annealing: Track problematic repos
    failure_count = Column(Integer, default=0)
    last_failure_at = Column(DateTime)
    last_failure_reason = Column(String)

    # Architecture
    architecture_report = Column(Text)
    architecture_diagram = Column(Text) # XML string for Draw.io
    
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    scan_runs = relationship("ScanRun", back_populates="repository")
    findings = relationship("Finding", back_populates="repository")
    file_commits = relationship("FileCommit", back_populates="repository")
    contributors = relationship("Contributor", back_populates="repository")
    languages = relationship("LanguageStat", back_populates="repository")
    dependencies = relationship("Dependency", back_populates="repository")


class FileCommit(Base):
    """Tracks the last commit information for specific files in a repository.
    Used to provide file-level 'Last Commit' data for findings.
    """
    __tablename__ = "file_commits"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    repository_id = Column(UUID(as_uuid=True), ForeignKey("repositories.id"), nullable=False)
    file_path = Column(Text, nullable=False)
    
    # Commit information from GitHub API
    last_commit_sha = Column(String(40))
    last_commit_date = Column(DateTime)
    last_commit_author = Column(String)
    last_commit_message = Column(Text)
    
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    repository = relationship("Repository", back_populates="file_commits")

    __table_args__ = (
        UniqueConstraint('repository_id', 'file_path', name='uq_file_commits_repo_path'),
    )


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    api_id = Column(Integer, Sequence('scan_runs_api_id_seq'), unique=True)
    repository_id = Column(UUID(as_uuid=True), ForeignKey("repositories.id"))
    scan_type = Column(String)
    status = Column(String)
    triggered_by = Column(String)
    trigger_reference = Column(String)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    duration_seconds = Column(Integer)
    findings_count = Column(Integer)
    new_findings_count = Column(Integer)
    resolved_findings_count = Column(Integer)
    architecture_overview = Column(Text)
    scan_config = Column(JSONB)
    error_message = Column(Text)
    created_at = Column(DateTime, server_default=func.now())

    repository = relationship("Repository", back_populates="scan_runs")
    findings = relationship("Finding", back_populates="scan_run")

class Finding(Base):
    __tablename__ = "findings"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    api_id = Column(Integer, Sequence('findings_api_id_seq'), unique=True)
    finding_uuid = Column(UUID(as_uuid=True), unique=True, server_default=text("gen_random_uuid()"))
    repository_id = Column(UUID(as_uuid=True), ForeignKey("repositories.id"))
    scan_run_id = Column(UUID(as_uuid=True), ForeignKey("scan_runs.id"))
    
    scanner_name = Column(String)
    finding_type = Column(String)
    severity = Column(String)
    title = Column(Text, nullable=False)
    description = Column(Text)
    
    file_path = Column(Text)
    line_start = Column(Integer)
    line_end = Column(Integer)
    code_snippet = Column(Text)
    
    cve_id = Column(String)
    cwe_id = Column(String)
    package_name = Column(String)
    package_version = Column(String)
    fixed_version = Column(String)
    
    status = Column(String, default='open')
    resolution = Column(String)
    resolution_notes = Column(Text)
    
    assigned_to = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    assigned_at = Column(DateTime)
    jira_ticket_key = Column(String)
    jira_ticket_url = Column(Text)
    
    ai_remediation_text = Column(Text)
    ai_remediation_diff = Column(Text)
    ai_confidence_score = Column(Numeric(3, 2))
    
    first_seen_at = Column(DateTime, server_default=func.now())
    last_seen_at = Column(DateTime, server_default=func.now())
    resolved_at = Column(DateTime)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    repository = relationship("Repository", back_populates="findings")
    scan_run = relationship("ScanRun", back_populates="findings")
    assignee = relationship("User", back_populates="assigned_findings")
    history = relationship("FindingHistory", back_populates="finding")
    comments = relationship("FindingComment", back_populates="finding")
    remediations = relationship("Remediation", back_populates="finding")

class Remediation(Base):
    __tablename__ = "remediations"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    api_id = Column(Integer, Sequence('remediations_api_id_seq'), unique=True)
    finding_id = Column(UUID(as_uuid=True), ForeignKey("findings.id"))
    
    remediation_text = Column(Text)
    diff = Column(Text)
    confidence = Column(Numeric(3, 2))
    
    created_at = Column(DateTime, server_default=func.now())
    
    finding = relationship("Finding", back_populates="remediations")

class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    api_id = Column(Integer, Sequence('users_api_id_seq'), unique=True)
    username = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True, nullable=False)
    full_name = Column(String)
    role = Column(String)
    github_username = Column(String)
    jira_username = Column(String)
    is_active = Column(Boolean, default=True)
    last_login_at = Column(DateTime)
    created_at = Column(DateTime, server_default=func.now())

    assigned_findings = relationship("Finding", back_populates="assignee")

class FindingHistory(Base):
    __tablename__ = "finding_history"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    api_id = Column(Integer, Sequence('finding_history_api_id_seq'), unique=True)
    finding_id = Column(UUID(as_uuid=True), ForeignKey("findings.id"))
    changed_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    change_type = Column(String)
    old_value = Column(Text)
    new_value = Column(Text)
    comment = Column(Text)
    change_metadata = Column(JSONB)
    created_at = Column(DateTime, server_default=func.now())

    finding = relationship("Finding", back_populates="history")

class FindingComment(Base):
    __tablename__ = "finding_comments"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    api_id = Column(Integer, Sequence('finding_comments_api_id_seq'), unique=True)
    finding_id = Column(UUID(as_uuid=True), ForeignKey("findings.id"))
    author_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    comment_text = Column(Text, nullable=False)
    is_internal = Column(Boolean, default=True)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now())

    finding = relationship("Finding", back_populates="comments")

class SystemConfig(Base):
    __tablename__ = "system_config"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    key = Column(String, unique=True, nullable=False)
    value = Column(Text)
    description = Column(Text)
    is_encrypted = Column(Boolean, default=False)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

class ArchitectureVersion(Base):
    __tablename__ = "architecture_versions"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    repository_id = Column(UUID(as_uuid=True), ForeignKey("repositories.id"))
    version_number = Column(Integer, nullable=False)
    report_content = Column(Text)
    diagram_code = Column(Text)
    description = Column(Text)
    created_at = Column(DateTime, server_default=func.now())
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)

    repository = relationship("Repository", back_populates="architecture_versions")
    creator = relationship("User")

class Contributor(Base):
    __tablename__ = "contributors"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    repository_id = Column(UUID(as_uuid=True), ForeignKey("repositories.id"))
    name = Column(String, nullable=False)
    email = Column(String)
    github_username = Column(String)
    commits = Column(Integer, default=0)
    commit_percentage = Column(Numeric(5, 2))
    last_commit_at = Column(DateTime)
    languages = Column(JSONB)  # Store inferred languages as JSON array

    # Enhanced file tracking with severity data
    # Format: [{"path": "src/api.py", "severity": "high", "findings_count": 3}, ...]
    files_contributed = Column(JSONB, default=[])
    folders_contributed = Column(JSONB, default=[])  # ["src", "tests", "config", ...]

    # Risk and AI analysis
    risk_score = Column(Integer, default=0)  # 0-100 calculated risk
    ai_summary = Column(Text)  # AI-generated contributor analysis

    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    repository = relationship("Repository", back_populates="contributors")

class LanguageStat(Base):
    __tablename__ = "language_stats"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    repository_id = Column(UUID(as_uuid=True), ForeignKey("repositories.id"))
    name = Column(String, nullable=False)
    files = Column(Integer, default=0)
    lines = Column(Integer, default=0) # Code lines
    blanks = Column(Integer, default=0)
    comments = Column(Integer, default=0)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    repository = relationship("Repository", back_populates="languages")

class Dependency(Base):
    __tablename__ = "dependencies"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    repository_id = Column(UUID(as_uuid=True), ForeignKey("repositories.id"))
    name = Column(String, nullable=False)
    version = Column(String)
    type = Column(String) # e.g. npm, pypi, go
    package_manager = Column(String)
    license = Column(String)
    locations = Column(JSONB) # List of file paths
    source = Column(String) # Developer/Vendor
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    repository = relationship("Repository", back_populates="dependencies")

from sqlalchemy import UniqueConstraint

# ... (imports are at top of file, need to ensure UniqueConstraint is imported or use sqlalchemy.UniqueConstraint if I can't add import easily)

class ComponentAnalysis(Base):
    __tablename__ = "component_analysis"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    package_name = Column(String, nullable=False)
    version = Column(String, nullable=False)
    package_manager = Column(String, nullable=False)
    
    analysis_text = Column(Text)
    vulnerability_summary = Column(Text)
    severity = Column(String)
    exploitability = Column(String)
    fixed_version = Column(String)
    
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    # Unique constraint to ensure we don't analyze the same package version multiple times
    __table_args__ = (
        UniqueConstraint('package_name', 'version', 'package_manager', name='uq_component_analysis'),
    )

# Update Repository relationship
Repository.architecture_versions = relationship("ArchitectureVersion", back_populates="repository", order_by="desc(ArchitectureVersion.version_number)")
Repository.contributors = relationship("Contributor", back_populates="repository", cascade="all, delete-orphan")
Repository.languages = relationship("LanguageStat", back_populates="repository", cascade="all, delete-orphan")
Repository.dependencies = relationship("Dependency", back_populates="repository", cascade="all, delete-orphan")


# =============================================================================
# CONTRIBUTOR PROFILE - Unified Identity Management
# =============================================================================

class ContributorProfile(Base):
    """
    Unified contributor identity that aggregates all aliases (emails, usernames).
    Designed to integrate with Entra ID for employment status verification.
    """
    __tablename__ = "contributor_profiles"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    
    # Canonical identity (preferred display)
    display_name = Column(String, nullable=False)  # "Isaac Springer"
    primary_email = Column(String, unique=True)  # Preferred email (usually @sleepnumber.com)
    primary_github_username = Column(String)  # Primary GitHub handle
    
    # Entra ID / Azure AD integration
    entra_id_object_id = Column(String, unique=True)  # Azure AD Object ID (GUID)
    entra_id_upn = Column(String)  # User Principal Name (email-like identifier)
    entra_id_employee_id = Column(String)  # Employee ID from HR system
    entra_id_job_title = Column(String)
    entra_id_department = Column(String)
    entra_id_manager_upn = Column(String)  # Manager's UPN for escalation
    
    # Employment status
    employment_status = Column(String, default='unknown')  # active, inactive, terminated, contractor, unknown
    employment_verified_at = Column(DateTime)  # Last time we verified with Entra ID
    employment_start_date = Column(DateTime)
    employment_end_date = Column(DateTime)  # Termination date if known
    
    # Aggregated stats (computed from all linked Contributors)
    total_repos = Column(Integer, default=0)
    total_commits = Column(Integer, default=0)
    last_activity_at = Column(DateTime)  # Most recent commit across all repos
    first_activity_at = Column(DateTime)  # Earliest known commit
    
    # Risk assessment
    risk_score = Column(Integer, default=0)  # 0-100 calculated risk
    is_stale = Column(Boolean, default=False)  # No activity in 90+ days
    has_elevated_access = Column(Boolean, default=False)  # Has access to sensitive repos
    files_with_findings = Column(Integer, default=0)
    critical_files_count = Column(Integer, default=0)
    
    # AI analysis
    ai_identity_confidence = Column(Numeric(3, 2))  # Confidence in identity merging
    ai_summary = Column(Text)  # AI-generated profile analysis
    
    # Metadata
    is_verified = Column(Boolean, default=False)  # Manually verified by admin
    verified_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    verified_at = Column(DateTime)
    notes = Column(Text)  # Admin notes
    
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())
    
    # Relationships
    aliases = relationship("ContributorAlias", back_populates="profile", cascade="all, delete-orphan")
    verifier = relationship("User")


class ContributorAlias(Base):
    """
    An alias (email, username, name variation) linked to a ContributorProfile.
    Allows tracking all the different identities a single person has used.
    """
    __tablename__ = "contributor_aliases"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    profile_id = Column(UUID(as_uuid=True), ForeignKey("contributor_profiles.id"), nullable=False)
    
    # Identity information
    alias_type = Column(String, nullable=False)  # 'email', 'github_username', 'name'
    alias_value = Column(String, nullable=False)  # The actual value
    is_primary = Column(Boolean, default=False)  # Is this the preferred alias of its type?
    
    # Source tracking
    source = Column(String)  # 'git_log', 'github_api', 'entra_id', 'manual'
    first_seen_at = Column(DateTime)
    last_seen_at = Column(DateTime)
    
    # Match metadata
    match_confidence = Column(Numeric(3, 2))  # How confident was the matching algorithm
    match_reason = Column(String)  # 'exact_email', 'same_full_name', 'github_matches_email', etc.
    
    created_at = Column(DateTime, server_default=func.now())
    
    # Relationships
    profile = relationship("ContributorProfile", back_populates="aliases")
    
    __table_args__ = (
        UniqueConstraint('alias_type', 'alias_value', name='uq_contributor_alias'),
    )


# Add link from Contributor to ContributorProfile
Contributor.profile_id = Column(UUID(as_uuid=True), ForeignKey("contributor_profiles.id"), nullable=True)
Contributor.profile = relationship("ContributorProfile", backref="contributors")
