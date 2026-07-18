"""Errors raised by Phoenix durable jobs and scheduling."""


class PhoenixJobError(Exception):
    """Base class for scheduler failures."""


class JobAlreadyExistsError(PhoenixJobError):
    """Raised when a repository already contains the requested job id."""


class JobNotFoundError(PhoenixJobError):
    """Raised when a requested job does not exist."""


class JobRepositoryClosedError(PhoenixJobError):
    """Raised when a closed job repository is accessed."""


class JobPersistenceError(PhoenixJobError):
    """Raised when durable job state is malformed or unsupported."""


class JobSchedulerClosedError(PhoenixJobError):
    """Raised when a closed scheduler is accessed."""


class JobLeaseLostError(PhoenixJobError):
    """Raised when an execution result uses a stale or expired lease."""
