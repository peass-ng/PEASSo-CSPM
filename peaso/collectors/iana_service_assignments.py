"""Offline IANA TCP/UDP service assignment snapshot for the NSG service check.

The registry is a naming reference, not evidence of a running workload service.
"""
from __future__ import annotations

from functools import lru_cache
from importlib.resources import files
from json import loads
from types import MappingProxyType

SOURCE_URL = "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv"
SOURCE_LAST_MODIFIED = "Fri, 16 Oct 2026 04:01:56 GMT"
# SHA256 of the downloaded IANA CSV the packaged mapping was generated from (third-party provenance).
SOURCE_SHA256 = "b6afeefdc6b2c616f9a515d57819a558ebe33250b59b2700b3afc4a4ba1923f2"


@lru_cache(maxsize=1)
def _assignments():
    try:
        document = loads(files("peaso.collectors").joinpath("iana_service_assignments.json").read_bytes())
        return MappingProxyType({key: frozenset(names) for key, names in document["mapping"].items()})
    except (OSError, KeyError, TypeError, ValueError) as exc:
        raise ValueError("IANA assignment snapshot unavailable") from exc


def assigned_services(protocol: str, port: int) -> frozenset[str]:
    """Return active names assigned to this exact TCP/UDP port."""
    if protocol not in ("Tcp", "Udp") or type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("invalid protocol or port")
    return _assignments().get(f"{protocol.lower()}/{port}", frozenset())
