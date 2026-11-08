class CorsprobeError(Exception):
    """The scan could not run."""


class InputError(CorsprobeError):
    """The arguments or a URL list could not be used."""


class ProbeFailure(CorsprobeError):
    """One target could not be probed."""
