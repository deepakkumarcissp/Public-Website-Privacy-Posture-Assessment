"""Public Website Privacy Posture Assessment — DKCISSP."""

from .engine import PrivacyPostureAssessor, assess_website

__version__ = "1.0.0"
__all__ = ["PrivacyPostureAssessor", "assess_website", "__version__"]
