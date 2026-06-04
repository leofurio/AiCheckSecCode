"""AiCheckSecCode: Git repository security and hygiene crawler."""

from .auditor import AuditConfig, RepoAuditor

__version__ = "0.2.0"

__all__ = ["AuditConfig", "RepoAuditor", "__version__"]
