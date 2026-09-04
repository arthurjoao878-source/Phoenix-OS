"""RFC-0039 operator-facing configuration compiler.

The TOML document is operator state. It is parsed with a closed schema and
compiled into the existing typed inference contracts; it is never model input.
"""

from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from phoenix_os.inference.configuration import (
    InferenceProviderConfiguration,
    InferenceServiceConfiguration,
)
from phoenix_os.inference.contracts import (
    MAX_INFERENCE_IDENTIFIER_LENGTH,
    MAX_INFERENCE_PROVIDER_MODEL_NAME_LENGTH,
    ModelCapabilities,
    ModelDescriptor,
    ModelId,
)
from phoenix_os.inference.endpoints import ModelEndpointMode, ModelEndpointPolicy
from phoenix_os.inference.ollama import (
    OLLAMA_ENDPOINT_URL,
    OLLAMA_PORT,
    OLLAMA_PROVIDER_ID,
    OllamaModelBinding,
)

OPERATOR_CONFIG_SCHEMA_VERSION = 1
MAX_OPERATOR_CONFIG_BYTES = 262_144
MAX_OPERATOR_MODELS = 32
MAX_OPERATOR_WORKSPACES = 64
MAX_OPERATOR_PROFILES = 64
MAX_OPERATOR_PATH_TEXT = 32_768
MAX_OPERATOR_PATH_ITEMS = 256

_IDENTIFIER_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,127})$")
_ALLOWED_TOP_LEVEL = frozenset({"schema_version", "providers", "models", "workspaces", "profiles"})
_SCAFFOLD = """\
schema_version = 1

# Add only providers and models you explicitly intend Phoenix to use.
#
# [providers.ollama-local]
# kind = "ollama-local"
#
# [models.dev]
# provider = "ollama-local"
# provider_model_name = "qwen3:4b-instruct"
# expected_digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
#
# Development-checkout declarations are operator-owned configuration only.
#
# [workspaces.project]
# kind = "development-checkout"
# root = "C:/Projects/example"
# read_prefixes = ["src", "tests"]
# patch_prefixes = ["src", "tests"]
#
# [profiles.development]
# model = "dev"
# workspace = "project"
# context_paths = ["src/example.py"]
# allow_workspace_patch = false
"""


class OperatorConfigurationError(ValueError):
    """A content-free boundary error for invalid operator configuration."""


class OperatorConfigurationAbsentError(OperatorConfigurationError):
    """The explicitly selected operator configuration does not exist."""


@dataclass(frozen=True, slots=True)
class OperatorModelConfiguration:
    model_name: str
    provider_name: str
    provider_model_name: str
    expected_digest: str | None
    descriptor: ModelDescriptor
    binding: OllamaModelBinding


@dataclass(frozen=True, slots=True)
class OperatorWorkspaceConfiguration:
    workspace_name: str
    kind: str
    root: str
    read_prefixes: tuple[str, ...]
    patch_prefixes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class OperatorProfileConfiguration:
    profile_name: str
    model_name: str
    workspace_name: str
    context_paths: tuple[str, ...]
    allow_workspace_patch: bool


@dataclass(frozen=True, slots=True)
class OperatorConfiguration:
    source: Path
    inference: InferenceServiceConfiguration | None
    models: tuple[OperatorModelConfiguration, ...]
    workspaces: tuple[OperatorWorkspaceConfiguration, ...]
    profiles: tuple[OperatorProfileConfiguration, ...]

    def model(self, name: str) -> OperatorModelConfiguration:
        for model in self.models:
            if model.model_name == name:
                return model
        raise KeyError(name)

    def workspace(self, name: str) -> OperatorWorkspaceConfiguration:
        for workspace in self.workspaces:
            if workspace.workspace_name == name:
                return workspace
        raise KeyError(name)


def initialize_operator_configuration(path: Path) -> None:
    """Create a minimal commented schema-v1 scaffold, never overwriting a file."""

    destination = Path(path)
    try:
        with destination.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(_SCAFFOLD)
            stream.flush()
    except FileExistsError:
        raise
    except OSError as exception:
        raise OperatorConfigurationError(
            "operator configuration initialization failed"
        ) from exception


def load_operator_configuration(path: Path) -> OperatorConfiguration:
    """Parse and compile one explicit operator configuration path."""

    source = Path(path)
    try:
        resolved_source = source.resolve(strict=True)
        with resolved_source.open("rb") as stream:
            payload = stream.read(MAX_OPERATOR_CONFIG_BYTES + 1)
    except FileNotFoundError as exception:
        raise OperatorConfigurationAbsentError("operator configuration is absent") from exception
    except (OSError, RuntimeError) as exception:
        raise OperatorConfigurationError("operator configuration cannot be read") from exception

    if len(payload) > MAX_OPERATOR_CONFIG_BYTES:
        raise OperatorConfigurationError("operator configuration exceeds the supported size")
    try:
        text = payload.decode("utf-8")
        document = tomllib.loads(text)
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exception:
        raise OperatorConfigurationError("operator configuration is invalid") from exception

    try:
        return _compile_document(resolved_source, document)
    except OperatorConfigurationError:
        raise
    except (TypeError, ValueError, KeyError) as exception:
        raise OperatorConfigurationError("operator configuration is invalid") from exception


def project_operator_configuration(configuration: OperatorConfiguration) -> dict[str, object]:
    """Return a deterministic projection containing no credential material."""

    providers: dict[str, object] = {}
    if configuration.inference is not None:
        for provider in configuration.inference.providers:
            providers[str(provider.provider_id)] = {"kind": "ollama-local"}

    models = {
        model.model_name: {
            "provider": model.provider_name,
            "provider_model_name": model.provider_model_name,
            **(
                {"expected_digest": model.expected_digest}
                if model.expected_digest is not None
                else {}
            ),
        }
        for model in configuration.models
    }
    workspaces = {
        workspace.workspace_name: {
            "kind": workspace.kind,
            "root": workspace.root,
            "read_prefixes": list(workspace.read_prefixes),
            "patch_prefixes": list(workspace.patch_prefixes),
        }
        for workspace in configuration.workspaces
    }
    profiles = {
        profile.profile_name: {
            "model": profile.model_name,
            "workspace": profile.workspace_name,
            "context_paths": list(profile.context_paths),
            "allow_workspace_patch": profile.allow_workspace_patch,
        }
        for profile in configuration.profiles
    }
    return {
        "schema_version": OPERATOR_CONFIG_SCHEMA_VERSION,
        "source": {
            "kind": "explicit",
            "path": str(configuration.source),
        },
        "providers": providers,
        "models": models,
        "workspaces": workspaces,
        "profiles": profiles,
    }


def _compile_document(source: Path, document: object) -> OperatorConfiguration:
    root = _mapping(document, "root")
    _exact_keys(root, _ALLOWED_TOP_LEVEL, "root")
    version = root.get("schema_version")
    if type(version) is not int or version != OPERATOR_CONFIG_SCHEMA_VERSION:
        raise OperatorConfigurationError("unsupported operator configuration schema version")

    providers_document = _named_table(root, "providers")
    models_document = _named_table(root, "models")
    workspaces_document = _named_table(root, "workspaces")
    profiles_document = _named_table(root, "profiles")

    provider_names = _compile_providers(providers_document)
    models = _compile_models(models_document, provider_names)
    workspaces = _compile_workspaces(workspaces_document)
    profiles = _compile_profiles(profiles_document, models, workspaces)

    inference: InferenceServiceConfiguration | None = None
    if provider_names or models:
        if not provider_names or not models:
            raise OperatorConfigurationError(
                "configured inference requires both a provider and a model"
            )
        provider_configuration = InferenceProviderConfiguration(
            provider_id=OLLAMA_PROVIDER_ID,
            endpoint_policy=ModelEndpointPolicy(
                OLLAMA_ENDPOINT_URL,
                mode=ModelEndpointMode.LOOPBACK_HTTP,
                allowed_ports=frozenset({OLLAMA_PORT}),
            ),
        )
        inference = InferenceServiceConfiguration(
            providers=(provider_configuration,),
            models=tuple(model.descriptor for model in models),
            source="phoenix.operator",
        )

    return OperatorConfiguration(
        source=source,
        inference=inference,
        models=models,
        workspaces=workspaces,
        profiles=profiles,
    )


def _compile_providers(document: dict[str, object]) -> tuple[str, ...]:
    if len(document) > 1:
        raise OperatorConfigurationError("operator configuration supports one provider")
    normalized_names = _normalized_named_entries(document)
    providers: list[str] = []
    for name, value in normalized_names:
        item = _mapping(value, "provider")
        _exact_keys(item, frozenset({"kind"}), "provider")
        kind = _string(item.get("kind"), maximum=MAX_INFERENCE_IDENTIFIER_LENGTH)
        if kind != "ollama-local" or name != "ollama-local":
            raise OperatorConfigurationError("unsupported provider registration")
        providers.append(name)
    return tuple(providers)


def _compile_models(
    document: dict[str, object],
    provider_names: tuple[str, ...],
) -> tuple[OperatorModelConfiguration, ...]:
    if len(document) > MAX_OPERATOR_MODELS:
        raise OperatorConfigurationError("operator model count exceeds the supported maximum")
    provider_set = set(provider_names)
    result: list[OperatorModelConfiguration] = []
    for model_name, value in _normalized_named_entries(document):
        item = _mapping(value, "model")
        _exact_keys(
            item,
            frozenset({"provider", "provider_model_name", "expected_digest"}),
            "model",
        )
        provider_name = _identifier(item.get("provider"), "provider reference")
        if provider_name not in provider_set:
            raise OperatorConfigurationError("model references an unconfigured provider")
        provider_model_name = _string(
            item.get("provider_model_name"),
            maximum=MAX_INFERENCE_PROVIDER_MODEL_NAME_LENGTH,
        )
        expected_digest = _optional_string(item.get("expected_digest"), maximum=64)
        descriptor = ModelDescriptor(
            provider_id=OLLAMA_PROVIDER_ID,
            model_id=ModelId(model_name),
            provider_model_name=provider_model_name,
            capabilities=ModelCapabilities(complete=True, streaming=True),
        )
        binding = OllamaModelBinding(descriptor, expected_digest=expected_digest)
        result.append(
            OperatorModelConfiguration(
                model_name=model_name,
                provider_name=provider_name,
                provider_model_name=provider_model_name,
                expected_digest=expected_digest,
                descriptor=descriptor,
                binding=binding,
            )
        )
    return tuple(result)


def _compile_workspaces(
    document: dict[str, object],
) -> tuple[OperatorWorkspaceConfiguration, ...]:
    if len(document) > MAX_OPERATOR_WORKSPACES:
        raise OperatorConfigurationError("operator workspace count exceeds the supported maximum")
    result: list[OperatorWorkspaceConfiguration] = []
    for workspace_name, value in _normalized_named_entries(document):
        item = _mapping(value, "workspace")
        _exact_keys(
            item,
            frozenset({"kind", "root", "read_prefixes", "patch_prefixes"}),
            "workspace",
        )
        kind = _string(item.get("kind"), maximum=64)
        if kind != "development-checkout":
            raise OperatorConfigurationError("unsupported workspace kind")
        root = _normalize_host_path(_string(item.get("root"), maximum=MAX_OPERATOR_PATH_TEXT))
        read_prefixes = _logical_path_list(item.get("read_prefixes", []), "read_prefixes")
        patch_prefixes = _logical_path_list(item.get("patch_prefixes", []), "patch_prefixes")
        if any(
            not any(_within_prefix(patch_prefix, read_prefix) for read_prefix in read_prefixes)
            for patch_prefix in patch_prefixes
        ):
            raise OperatorConfigurationError("patch prefixes must be within read prefixes")
        result.append(
            OperatorWorkspaceConfiguration(
                workspace_name=workspace_name,
                kind=kind,
                root=root,
                read_prefixes=read_prefixes,
                patch_prefixes=patch_prefixes,
            )
        )
    return tuple(result)


def _compile_profiles(
    document: dict[str, object],
    models: tuple[OperatorModelConfiguration, ...],
    workspaces: tuple[OperatorWorkspaceConfiguration, ...],
) -> tuple[OperatorProfileConfiguration, ...]:
    if len(document) > MAX_OPERATOR_PROFILES:
        raise OperatorConfigurationError("operator profile count exceeds the supported maximum")
    model_names = {model.model_name for model in models}
    workspace_by_name = {workspace.workspace_name: workspace for workspace in workspaces}
    result: list[OperatorProfileConfiguration] = []
    for profile_name, value in _normalized_named_entries(document):
        item = _mapping(value, "profile")
        _exact_keys(
            item,
            frozenset({"model", "workspace", "context_paths", "allow_workspace_patch"}),
            "profile",
        )
        model_name = _identifier(item.get("model"), "model reference")
        workspace_name = _identifier(item.get("workspace"), "workspace reference")
        context_paths = _logical_path_list(item.get("context_paths", []), "context_paths")
        allow_workspace_patch = item.get("allow_workspace_patch", False)
        if type(allow_workspace_patch) is not bool:
            raise OperatorConfigurationError("allow_workspace_patch must be a boolean")
        if model_name not in model_names:
            raise OperatorConfigurationError("profile references an unconfigured model")
        workspace = workspace_by_name.get(workspace_name)
        if workspace is None:
            raise OperatorConfigurationError("profile references an unconfigured workspace")
        if any(
            not any(_within_prefix(path, prefix) for prefix in workspace.read_prefixes)
            for path in context_paths
        ):
            raise OperatorConfigurationError("profile context path is outside read prefixes")
        if allow_workspace_patch and not workspace.patch_prefixes:
            raise OperatorConfigurationError(
                "workspace patch cannot be enabled without patch prefixes"
            )
        result.append(
            OperatorProfileConfiguration(
                profile_name=profile_name,
                model_name=model_name,
                workspace_name=workspace_name,
                context_paths=context_paths,
                allow_workspace_patch=allow_workspace_patch,
            )
        )
    return tuple(result)


def _normalized_named_entries(document: dict[str, object]) -> tuple[tuple[str, object], ...]:
    seen: set[str] = set()
    result: list[tuple[str, object]] = []
    for raw_name, value in document.items():
        normalized = _identifier(raw_name, "configuration identifier")
        if normalized in seen:
            raise OperatorConfigurationError("duplicate normalized configuration identifier")
        seen.add(normalized)
        result.append((normalized, value))
    result.sort(key=lambda item: item[0])
    return tuple(result)


def _named_table(document: dict[str, object], key: str) -> dict[str, object]:
    value = document.get(key, {})
    return dict(_mapping(value, key))


def _mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise OperatorConfigurationError(f"{label} must be a table")
    if any(not isinstance(key, str) for key in value):
        raise OperatorConfigurationError(f"{label} contains a non-string key")
    return value


def _exact_keys(
    document: dict[str, object],
    allowed: frozenset[str],
    label: str,
) -> None:
    unknown = set(document).difference(allowed)
    if unknown:
        raise OperatorConfigurationError(f"{label} contains unsupported fields")


def _identifier(value: object, label: str) -> str:
    text = _string(value, maximum=MAX_INFERENCE_IDENTIFIER_LENGTH).lower()
    if _IDENTIFIER_PATTERN.fullmatch(text) is None:
        raise OperatorConfigurationError(f"{label} is invalid")
    return text


def _string(value: object, *, maximum: int) -> str:
    if not isinstance(value, str):
        raise OperatorConfigurationError("configuration value must be a string")
    normalized = value.strip()
    if (
        not normalized
        or len(normalized) > maximum
        or any(ord(character) < 32 for character in normalized)
    ):
        raise OperatorConfigurationError("configuration string is invalid")
    return normalized


def _optional_string(value: object, *, maximum: int) -> str | None:
    if value is None:
        return None
    return _string(value, maximum=maximum)


def _logical_path_list(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise OperatorConfigurationError(f"{label} must be a list")
    if len(value) > MAX_OPERATOR_PATH_ITEMS:
        raise OperatorConfigurationError(f"{label} exceeds the supported item count")
    result: list[str] = []
    seen: set[str] = set()
    for item in value:
        path = _string(item, maximum=MAX_OPERATOR_PATH_TEXT)
        if "\\" in path:
            raise OperatorConfigurationError(f"{label} must use logical POSIX paths")
        parsed = PurePosixPath(path)
        if (
            parsed.is_absolute()
            or path in {".", ".."}
            or any(part in {"", ".", ".."} for part in parsed.parts)
            or parsed.as_posix() != path
        ):
            raise OperatorConfigurationError(f"{label} contains a non-canonical logical path")
        if path in seen:
            raise OperatorConfigurationError(f"{label} contains a duplicate logical path")
        seen.add(path)
        result.append(path)
    return tuple(result)


def _within_prefix(path: str, prefix: str) -> bool:
    return path == prefix or path.startswith(prefix + "/")


def _normalize_host_path(value: str) -> str:
    namespace_form = value.replace("/", "\\")
    if os.name == "nt" and (
        namespace_form.startswith("\\\\?\\") or namespace_form.startswith("\\\\.\\")
    ):
        raise OperatorConfigurationError("development checkout root uses a device namespace")
    if not Path(value).is_absolute():
        raise OperatorConfigurationError("development checkout root must be native and absolute")
    normalized = os.path.abspath(value)
    if not Path(normalized).is_absolute():
        raise OperatorConfigurationError("development checkout root must be native and absolute")
    return normalized
