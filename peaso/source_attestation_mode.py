"""Process policy for repeated source self-attestation.

Every pinned verifier still runs its complete proof the first time it is
called in a process.  Production then trusts that proof for the immutable
image instead of re-reading, re-parsing and re-compiling the same sources on
every nested call.  Tests and CI export ``PEASO_SOURCE_ATTESTATION=always`` to
re-prove on every call, which also catches live rebinding after import.
"""
import os

ALWAYS = os.environ.get('PEASO_SOURCE_ATTESTATION', '').strip().lower() == 'always'


def repeat(proven):
    """Return True when a verifier that already proved itself must run again."""
    return ALWAYS or not proven
