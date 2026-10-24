class ScanError(Exception):
    """The scan could not finish because of how it was invoked."""


class ConfigError(ScanError):
    """A config file or flag is present but not usable."""


class TargetError(ScanError):
    """The DAST or webhook target was rejected before a request was sent."""


class PublishError(ScanError):
    """A report was produced but could not be delivered."""
