class ReconError(Exception):
    """The inspection could not run."""


class TargetError(ReconError):
    """The host was rejected, or the URL could not be used."""


class PolicyError(TargetError):
    """The target is outside the single host the operator named."""


class ConnectError(TargetError):
    """The host was in scope, but a connection failed."""
