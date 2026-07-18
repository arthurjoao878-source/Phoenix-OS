"""Errors raised by Phoenix durable workflow graphs."""


class PhoenixWorkflowError(Exception):
    """Base class for workflow definition and persistence failures."""


class WorkflowDefinitionError(PhoenixWorkflowError):
    """Raised when a workflow definition is malformed."""


class WorkflowDuplicateStepError(WorkflowDefinitionError):
    """Raised when a workflow declares the same step identifier twice."""


class WorkflowDependencyError(WorkflowDefinitionError):
    """Raised when a workflow dependency is missing or invalid."""


class WorkflowCycleError(WorkflowDefinitionError):
    """Raised when workflow dependencies contain a directed cycle."""


class WorkflowAlreadyExistsError(PhoenixWorkflowError):
    """Raised when a repository already contains a workflow id."""


class WorkflowNotFoundError(PhoenixWorkflowError):
    """Raised when a requested workflow does not exist."""


class WorkflowConflictError(PhoenixWorkflowError):
    """Raised when an optimistic workflow revision is stale."""


class WorkflowPersistenceError(PhoenixWorkflowError):
    """Raised when persisted workflow data is invalid or unsupported."""


class WorkflowRepositoryClosedError(PhoenixWorkflowError):
    """Raised when a closed workflow repository is accessed."""


class WorkflowOrchestratorClosedError(PhoenixWorkflowError):
    """Raised when a closed workflow orchestrator is accessed."""


class WorkflowWorkerStateError(PhoenixWorkflowError):
    """Raised when a workflow worker lifecycle operation is invalid."""
