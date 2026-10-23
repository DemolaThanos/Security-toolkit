class ReconError(Exception):
    """The inspection could not run."""


class TargetError(ReconError):
    """The host was rejected, or the URL could not be used."""
