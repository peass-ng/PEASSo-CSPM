"""Skip real-engine secret scanner tests when the pinned releases are absent.

The scanners report a different installed release (for example a newer
Homebrew trufflehog) as ``unavailable``, which turns clean inputs into UNKNOWN
and drops single-engine matches.  CI provisions the exact pinned releases.
"""
import pytest

from peaso import secret_scanning as scanning


def require_pinned_scanners():
    """Real-engine tests need the exact scanner releases that CI provisions."""
    try:
        scanning._trufflehog()
        scanning._kingfisher()
    except Exception as error:
        pytest.skip(f'pinned secret scanners unavailable (trufflehog {scanning.TRUFFLEHOG_VERSION} on PATH, '
                    f'kingfisher-secret-scanner {scanning.KINGFISHER_VERSION}): {type(error).__name__}: {error}')
