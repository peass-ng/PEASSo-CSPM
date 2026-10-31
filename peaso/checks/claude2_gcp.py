"""claude2_gcp partition: native GCP predicates (see docs/checks.md)."""
from . import claude2_gcp_logging, claude2_gcp_services  # noqa: F401
from .claude2_gcp_common import CHECK_IDS, PREFIX

__all__ = ["CHECK_IDS", "PREFIX"]
