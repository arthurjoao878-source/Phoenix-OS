# ADR-0061: Server-owned configured application profiles

- **Status:** Accepted
- **Date:** 2026-08-18
- **Related:** RFC-0032

## Context

Launching a desktop application is an external operating-system effect. Accepting an
executable path, command line, working directory, environment block, shell verb,
elevation request, package identifier, or native launcher from model-controlled input
would turn a narrow application-launch feature into arbitrary command execution.

Phoenix still needs a stable way for policy and callers to name applications that a
deployment has intentionally made launchable.

## Decision

Application launch is profile-based and uses server-owned `HostApplicationId` profiles.

Trusted Phoenix configuration maps each stable application identity to adapter-owned
launch configuration. Public launch requests name only the configured application
identity and bounded Phoenix-owned request metadata. The model cannot create, replace,
or mutate the configured profile.

The initial launch surface never accepts model-selected executable paths, command
lines, working directories, environment mutation, shell or elevation verbs, package
identifiers, or native launchers. It does not expose a generic argument channel.

If a future design adds application arguments, each application must define an
explicit bounded reviewed schema. A generic command-line escape hatch remains outside
this decision.

A successful launch result is descriptive data and grants no subsequent process,
window, focus, close, clipboard, or other host authority. Launch is never
transparently retried; uncertainty after effect admission becomes an indeterminate
outcome instead of an automatic second launch.

## Consequences

- Policy can authorize one configured application without authorizing arbitrary
  executable selection.
- Deployment configuration, not model output, chooses what native launch target a
  `HostApplicationId` represents.
- Agent tools can expose a finite application identity without exposing shell or
  command-line authority.
- Changing launch profiles is a trusted configuration operation outside model control.
- Future argument support requires a new reviewed bounded schema rather than widening
  the existing request into generic execution.

## Alternatives considered

- **Accept executable paths directly.** Rejected because path selection becomes command
  execution authority.
- **Accept an arbitrary command line or shell string.** Rejected because parsing and
  shell interpretation defeat the bounded application-profile boundary.
- **Discover installed applications and trust their metadata.** Rejected because
  discovered host metadata is data, not trusted Phoenix configuration.
- **Retry failed or uncertain launches automatically.** Rejected because an admitted
  launch may already have produced the external effect.

## Supersession criteria

A replacement must preserve server-owned stable application identities, trusted
configuration as the only launch-target mapping authority, no arbitrary executable or
command-line escape hatch, bounded reviewed future arguments, descriptive launch
results with no derived authority, and no transparent replay of uncertain launches.
