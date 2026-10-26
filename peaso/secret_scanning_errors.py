"""Fixed offline scanner failure identities; never retain tool output."""

class ScannerStdoutBound(ValueError):
    """The native subprocess stdout crossed the unchanged output-byte ceiling."""
