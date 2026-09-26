"""One-shot RFC-0039 local operator bootstrap for standalone task execution."""

from __future__ import annotations

import asyncio
import getpass
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from phoenix_os.agent.authorization import AGENT_RUN_ACTION, TOOL_INVOKE_ACTION
from phoenix_os.agent.durable_authorization import AGENT_CANCEL_ACTION
from phoenix_os.agent.workspace_authorization import (
    WORKSPACE_LIST_ACTION,
    WORKSPACE_PATCH_ACTION,
    WORKSPACE_READ_ACTION,
)
from phoenix_os.control_plane.operator_configuration import (
    OperatorConfiguration,
    OperatorConfigurationAbsentError,
    OperatorConfigurationError,
    load_operator_configuration,
)
from phoenix_os.control_plane.operator_contracts import (
    ControlPlaneOperatorRecord,
    ControlPlaneOperatorRole,
    ControlPlaneOperatorToken,
)
from phoenix_os.control_plane.operator_state import StateControlPlaneOperatorRegistry
from phoenix_os.inference.authorization import INFERENCE_MODEL_ACTION
from phoenix_os.state.sqlite import SQLiteStateStore

_BOOTSTRAP_USERNAME = "local-maintainer"
_BOOTSTRAP_DISPLAY_NAME = "Local Maintainer"
_CREDENTIAL_PROMPT = "New operator credential: "
_CREDENTIAL_CONFIRM_PROMPT = "Confirm operator credential: "


def run_operator_bootstrap(path: Path) -> int:
    """Create the first standalone task operator from hidden terminal input."""

    try:
        configuration = load_operator_configuration(path)
    except OperatorConfigurationAbsentError:
        print("phoenix: configuration absent", file=sys.stderr)
        return 3
    except OperatorConfigurationError:
        print("phoenix: configuration invalid", file=sys.stderr)
        return 3

    if configuration.runtime is None:
        print("phoenix: durable state configuration required", file=sys.stderr)
        return 3
    if not configuration.profiles:
        print("phoenix: task profile configuration required", file=sys.stderr)
        return 3

    try:
        if not asyncio.run(_registry_is_empty(configuration)):
            print("phoenix: operator registry already initialized", file=sys.stderr)
            return 4
    except Exception:
        print("phoenix: operator bootstrap unavailable", file=sys.stderr)
        return 5

    first = getpass.getpass(_CREDENTIAL_PROMPT)
    second = getpass.getpass(_CREDENTIAL_CONFIRM_PROMPT)
    if first != second:
        first = ""
        second = ""
        print("phoenix: operator credential invalid", file=sys.stderr)
        return 3

    try:
        token = ControlPlaneOperatorToken(first)
    except ValueError:
        first = ""
        second = ""
        print("phoenix: operator credential invalid", file=sys.stderr)
        return 3
    finally:
        second = ""

    first = ""

    try:
        created, permissions = asyncio.run(_create_first_operator(configuration, token))
    except Exception:
        print("phoenix: operator bootstrap failed", file=sys.stderr)
        return 5

    if not created:
        print("phoenix: operator registry already initialized", file=sys.stderr)
        return 4

    print(
        json.dumps(
            {
                "operator": "created",
                "username": _BOOTSTRAP_USERNAME,
                "role": ControlPlaneOperatorRole.MAINTAINER.value,
                "task_permissions": sorted(permissions),
            },
            sort_keys=True,
        )
    )
    return 0


async def _registry_is_empty(configuration: OperatorConfiguration) -> bool:
    runtime = configuration.runtime
    if runtime is None:
        raise ValueError("durable state configuration required")
    store = SQLiteStateStore(runtime.durable_state_path)
    registry = StateControlPlaneOperatorRegistry(store, capacity=1)
    try:
        return (await registry.snapshot()).operators == 0
    finally:
        await store.close()


async def _create_first_operator(
    configuration: OperatorConfiguration,
    token: ControlPlaneOperatorToken,
) -> tuple[bool, frozenset[str]]:
    runtime = configuration.runtime
    if runtime is None:
        raise ValueError("durable state configuration required")

    permissions = _task_permissions(configuration)
    store = SQLiteStateStore(runtime.durable_state_path)
    registry = StateControlPlaneOperatorRegistry(store, capacity=1)
    try:
        if (await registry.snapshot()).operators != 0:
            return False, permissions

        now = datetime.now(UTC)
        record = ControlPlaneOperatorRecord(
            id=uuid4(),
            username=_BOOTSTRAP_USERNAME,
            display_name=_BOOTSTRAP_DISPLAY_NAME,
            role=ControlPlaneOperatorRole.MAINTAINER,
            token_digest=token.digest,
            additional_permissions=permissions,
            created_at=now,
            updated_at=now,
        )
        await registry.add(record)

        persisted = await registry.get_by_username(_BOOTSTRAP_USERNAME)
        if (
            persisted is None
            or persisted.token_digest != token.digest
            or persisted.additional_permissions != permissions
        ):
            raise RuntimeError("operator bootstrap verification failed")
        return True, permissions
    finally:
        await store.close()


def _task_permissions(configuration: OperatorConfiguration) -> frozenset[str]:
    permissions = {
        AGENT_RUN_ACTION,
        AGENT_CANCEL_ACTION,
        INFERENCE_MODEL_ACTION,
        TOOL_INVOKE_ACTION,
        WORKSPACE_LIST_ACTION,
        WORKSPACE_READ_ACTION,
    }
    if any(profile.allow_workspace_patch for profile in configuration.profiles):
        permissions.add(WORKSPACE_PATCH_ACTION)
    return frozenset(permissions)
