"""claude_gcp_k8s partition: native GCP and Kubernetes predicates (see docs/checks.md)."""
from . import claude_gcp_k8s_compute, claude_gcp_k8s_iam, claude_gcp_k8s_k8s  # noqa: F401
from .claude_gcp_k8s_common import CHECK_IDS, PREFIXES

__all__ = ["CHECK_IDS", "PREFIXES"]
