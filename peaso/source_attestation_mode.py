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


_ONCE = {}


def prove_once(verifier, *args, **kwargs):
    """Run a pinned verifier on a per-evaluation path.

    Production reuses the first successful proof of this exact verifier object
    and arguments for the rest of the process; a failed proof is never cached
    and raises again on the next call.  With ``always`` every call re-proves.
    """
    key = (verifier, args, tuple(sorted(kwargs.items())))
    if not repeat(key in _ONCE):
        return
    verifier(*args, **kwargs)
    _ONCE[key] = True
