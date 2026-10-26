"""Process policy for pinned source self-attestation.

``PEASO_SOURCE_ATTESTATION`` selects one of three modes:

``trusted`` (default)
    The process runs an immutable worker image built from a CI-verified
    commit, and that image build imports the engine in ``always`` mode, so a
    tree that fails any proof never becomes an image.  Pure verification is
    therefore skipped entirely, even on the first call; only the work that
    builds what the runtime needs still runs (see ``peaso.trusted_sources``).
``once``
    Every pinned verifier runs its complete proof the first time it is called
    in a process and reuses that proof for repeated nested calls.
``always``
    Tests, CI and the image build re-prove on every call, which also catches
    live rebinding after import.

An unrecognised value fails closed to ``always``.
"""
import os

_REQUESTED = os.environ.get('PEASO_SOURCE_ATTESTATION', '').strip().lower() or 'trusted'
MODE = _REQUESTED if _REQUESTED in ('trusted', 'once', 'always') else 'always'
ALWAYS = MODE == 'always'
TRUSTED = MODE == 'trusted'


def repeat(proven):
    """Return True when a verifier that already proved itself must run again."""
    return ALWAYS or not proven


_ONCE = {}


def prove_once(verifier, *args, **kwargs):
    """Run a pinned verifier on a per-evaluation path.

    ``once`` reuses the first successful proof of this exact verifier object
    and arguments for the rest of the process; a failed proof is never cached
    and raises again on the next call.  ``always`` re-proves on every call and
    ``trusted`` does not re-prove the immutable image at all.
    """
    if TRUSTED:
        return
    key = (verifier, args, tuple(sorted(kwargs.items())))
    if not repeat(key in _ONCE):
        return
    verifier(*args, **kwargs)
    _ONCE[key] = True
