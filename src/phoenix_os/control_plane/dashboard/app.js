"use strict";

const state = {
  legacyToken: "",
  csrf: "",
  cursor: 0,
  connected: false,
  refreshTimer: null,
  eventLoop: null,
  operations: {},
  me: null,
  operatorMode: false,
  selectedServiceAccount: null,
  webhookSubscriptions: new Map(),
};

const byId = (id) => document.getElementById(id);
const text = (id, value) => { byId(id).textContent = String(value); };
const formatTime = (value) => value ? new Date(value).toLocaleString() : "—";
const statusClass = (value) => `status status-${String(value).replaceAll(" ", "_")}`;
const newKey = () => `dashboard-${crypto.randomUUID()}`;

function hasPermission(permission) {
  return Boolean(
    state.me
    && state.me.permissions.includes(permission)
  );
}

async function request(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (state.legacyToken && !headers.has("Authorization")) {
    headers.set("Authorization", `Bearer ${state.legacyToken}`);
  }
  headers.set("Accept", "application/json");
  const response = await fetch(path, {
    ...options,
    headers,
    cache: "no-store",
    credentials: "same-origin",
  });
  const rotatedCsrf = response.headers.get("X-Phoenix-CSRF");
  if (rotatedCsrf) state.csrf = rotatedCsrf;
  const payload = await response.json();
  if (response.status === 401 || response.status === 403) {
    const error = new Error(response.status === 401 ? "unauthorized" : (payload.error || "forbidden"));
    error.payload = payload;
    throw error;
  }
  if (!response.ok && response.status !== 422) {
    const error = new Error(payload.error || `http_${response.status}`);
    error.payload = payload;
    throw error;
  }
  return payload;
}

const api = (path) => request(path);

async function exchangeOperatorCredential(credential) {
  const response = await fetch("/v1/control-plane/operator/login", {
    method: "POST",
    headers: { Authorization: `Bearer ${credential}`, Accept: "application/json" },
    cache: "no-store",
    credentials: "same-origin",
  });
  const payload = await response.json();
  if (response.ok) {
    state.csrf = response.headers.get("X-Phoenix-CSRF") || "";
    return payload;
  }
  if ([404, 405].includes(response.status) || payload.error === "not_found" || payload.error === "method_not_allowed") return null;
  throw new Error(response.status === 401 ? "unauthorized" : (payload.error || `http_${response.status}`));
}

async function issueLegacyCsrf() {
  const payload = await request("/v1/control-plane/csrf", { method: "POST" });
  state.csrf = payload.csrf_token;
}

async function ensureCsrf() {
  if (state.csrf) return;
  if (state.operatorMode) throw new Error("session_csrf_unavailable");
  await issueLegacyCsrf();
}

async function stepUp(action) {
  const credential = window.prompt("Re-enter your durable operator credential to confirm this sensitive action.");
  if (!credential) throw new Error("step_up_cancelled");
  await ensureCsrf();
  const grant = await request("/v1/control-plane/operator/step-up", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${credential.trim()}`,
      "Content-Type": "application/json",
      "X-Phoenix-CSRF": state.csrf,
    },
    body: JSON.stringify({ action }),
  });
  return grant.step_up_proof;
}

async function operatorCommand(path, body, stepUpAction = "") {
  await ensureCsrf();
  const headers = new Headers({
    "Content-Type": "application/json",
    "X-Phoenix-CSRF": state.csrf,
  });
  if (stepUpAction) headers.set("X-Phoenix-Step-Up", await stepUp(stepUpAction));
  return request(path, { method: "POST", headers, body: JSON.stringify(body) });
}

async function command(path, body, key = newKey(), confirmation = "") {
  await ensureCsrf();
  const headers = new Headers({
    "Content-Type": "application/json",
    "Idempotency-Key": key,
    "X-Phoenix-CSRF": state.csrf,
  });
  if (confirmation) headers.set("X-Phoenix-Confirmation", confirmation);
  try {
    return await request(path, { method: "POST", headers, body: JSON.stringify(body) });
  } catch (error) {
    if (error.message === "request_rejected" && !state.operatorMode) await issueLegacyCsrf();
    throw error;
  }
}

function setConnected(connected, label) {
  state.connected = connected;
  byId("connection-dot").className = `status-dot ${connected ? "status-online" : "status-offline"}`;
  text("connection-label", label || (connected ? "Connected" : "Disconnected"));
  byId("login-panel").classList.toggle("hidden", connected);
  byId("dashboard").classList.toggle("hidden", !connected);
}

function renderSnapshot(snapshot) {
  text("health", snapshot.health);
  byId("health").className = `status-${snapshot.health}`;
  text("runtime-state", snapshot.runtime.state);
  byId("runtime-state").className = statusClass(snapshot.runtime.state);
  text("runtime-id", `Runtime ${snapshot.runtime.runtime_id}`);
  text("jobs-total", snapshot.jobs.total);
  text("jobs-summary", `${snapshot.jobs.running} running · ${snapshot.jobs.succeeded} succeeded · ${snapshot.jobs.dead_letter} dead-letter`);
  text("workflows-total", snapshot.workflows.total);
  text("workflows-summary", `${snapshot.workflows.running} running · ${snapshot.workflows.succeeded} succeeded · ${snapshot.workflows.failed} failed`);
  const journal = snapshot.command_journal;
  text("commands-total", journal ? journal.entries : 0);
  text("commands-summary", journal ? `${journal.pending + journal.executing} active · ${journal.succeeded} succeeded · ${journal.failed + journal.rejected} unsuccessful` : "Unavailable");
  text("last-updated", `Updated ${formatTime(snapshot.generated_at)}`);
}

function operationButton(label, action, enabled) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = "small secondary";
  button.textContent = label;
  button.disabled = !enabled;
  if (enabled) button.addEventListener("click", action);
  return button;
}

function renderJobs(page) {
  const body = byId("jobs-table");
  body.replaceChildren(...page.items.map((job) => {
    const row = document.createElement("tr");
    const capability = document.createElement("td"); capability.textContent = job.capability;
    const status = document.createElement("td");
    const badge = document.createElement("span"); badge.className = statusClass(job.status); badge.textContent = job.status; status.append(badge);
    const attempts = document.createElement("td"); attempts.textContent = `${job.attempts}/${job.max_attempts}`;
    const next = document.createElement("td"); next.textContent = formatTime(job.next_run_at);
    const actions = document.createElement("td"); actions.className = "row-actions";
    const cancellable = ["scheduled", "running", "retrying"].includes(job.status);
    if (cancellable && state.operations["job.cancel"]) actions.append(operationButton("Cancel", () => cancelJob(job.id), true));
    if (job.status === "dead_letter" && state.operations["job.retry-dead-letter"]) actions.append(operationButton("Retry", () => retryJob(job.id), true));
    if (!actions.children.length) actions.textContent = "—";
    row.append(capability, status, attempts, next, actions); return row;
  }));
  text("jobs-page", `${page.page.returned} of ${page.page.total}`);
}

function renderWorkflows(page) {
  const body = byId("workflows-table");
  body.replaceChildren(...page.items.map((workflow) => {
    const row = document.createElement("tr");
    const name = document.createElement("td"); name.textContent = `${workflow.name} v${workflow.version}`;
    const status = document.createElement("td");
    const badge = document.createElement("span"); badge.className = statusClass(workflow.status); badge.textContent = workflow.status; status.append(badge);
    const revision = document.createElement("td"); revision.textContent = workflow.revision;
    const steps = document.createElement("td");
    const counts = workflow.steps.reduce((result, step) => { result[step.status] = (result[step.status] || 0) + 1; return result; }, {});
    steps.textContent = Object.entries(counts).map(([key, count]) => `${key}: ${count}`).join(" · ") || "0 total";
    const actions = document.createElement("td");
    if (["pending", "running"].includes(workflow.status) && state.operations["workflow.cancel"]) actions.append(operationButton("Cancel", () => cancelWorkflow(workflow.id), true));
    else actions.textContent = "—";
    row.append(name, status, revision, steps, actions); return row;
  }));
  text("workflows-page", `${page.page.returned} of ${page.page.total}`);
}

function renderStack(id, items, lineBuilder) {
  const list = byId(id);
  list.replaceChildren(...items.map((item) => {
    const li = document.createElement("li");
    const [primary, secondary, status] = lineBuilder(item);
    const line = document.createElement("div"); line.className = "stack-line";
    const strong = document.createElement("strong"); strong.textContent = primary; line.append(strong);
    if (status) { const badge = document.createElement("span"); badge.className = statusClass(status); badge.textContent = status; line.append(badge); }
    const detail = document.createElement("p"); detail.className = "muted"; detail.textContent = secondary;
    li.append(line, detail); return li;
  }));
}

function renderHistory(page) {
  const body = byId("commands-table");
  body.replaceChildren(...page.items.map((item) => {
    const row = document.createElement("tr");
    const requested = document.createElement("td"); requested.textContent = formatTime(item.requested_at);
    const action = document.createElement("td"); action.textContent = item.action;
    const target = document.createElement("td"); target.textContent = item.target;
    const status = document.createElement("td");
    const badge = document.createElement("span"); badge.className = statusClass(item.status); badge.textContent = item.status; status.append(badge);
    const result = document.createElement("td"); result.textContent = item.result_code || "—";
    const principal = document.createElement("td"); principal.textContent = item.principal;
    row.append(requested, action, target, status, result, principal); return row;
  }));
  text("commands-page", `${page.page.returned} of ${page.page.total}`);
}

function renderSessions(page) {
  const body = byId("sessions-table");
  const canRevoke = state.me && state.me.permissions.includes("control-plane.operator-sessions.revoke");
  body.replaceChildren(...page.items.map((item) => {
    const row = document.createElement("tr");
    const issued = document.createElement("td"); issued.textContent = formatTime(item.issued_at);
    const operator = document.createElement("td"); operator.textContent = item.username;
    const generation = document.createElement("td"); generation.textContent = item.generation;
    const status = document.createElement("td");
    const badge = document.createElement("span"); badge.className = statusClass(item.status); badge.textContent = item.status; status.append(badge);
    const lastSeen = document.createElement("td"); lastSeen.textContent = formatTime(item.last_seen_at);
    const reason = document.createElement("td"); reason.textContent = item.termination_reason || "—";
    const actions = document.createElement("td");
    if (item.status === "active" && canRevoke) actions.append(operationButton("End", () => revokeSession(item.session_id), true));
    else actions.textContent = "—";
    row.append(issued, operator, generation, status, lastSeen, reason, actions); return row;
  }));
  text("sessions-page", `${page.page.returned} of ${page.page.total}`);
}

function renderOperators(page) {
  const body = byId("operators-table");
  const can = (permission) => state.me && state.me.permissions.includes(permission);
  body.replaceChildren(...page.items.map((item) => {
    const row = document.createElement("tr");
    const identity = document.createElement("td");
    const strong = document.createElement("strong"); strong.textContent = item.display_name;
    const username = document.createElement("p"); username.className = "muted"; username.textContent = item.username;
    identity.append(strong, username);
    const role = document.createElement("td"); role.textContent = item.role;
    const status = document.createElement("td");
    const badge = document.createElement("span"); badge.className = statusClass(item.status); badge.textContent = item.status; status.append(badge);
    const revision = document.createElement("td"); revision.textContent = item.revision;
    const actions = document.createElement("td"); actions.className = "row-actions";
    if (item.status !== "revoked" && can("control-plane.operators.update")) actions.append(operationButton("Edit", () => updateOperator(item), true));
    if (item.status === "active" && can("control-plane.operators.disable")) actions.append(operationButton("Disable", () => operatorLifecycle(item, "disable"), true));
    if (item.status === "disabled" && can("control-plane.operators.disable")) actions.append(operationButton("Reactivate", () => operatorLifecycle(item, "reactivate"), true));
    if (item.status !== "revoked" && can("control-plane.operators.rotate")) actions.append(operationButton("Rotate", () => rotateOperator(item), true));
    if (item.status !== "revoked" && can("control-plane.operator-sessions.revoke")) actions.append(operationButton("End sessions", () => revokeOperatorSessions(item), true));
    if (item.status !== "revoked" && can("control-plane.operators.revoke")) actions.append(operationButton("Revoke", () => operatorLifecycle(item, "revoke"), true));
    if (!actions.children.length) actions.textContent = "—";
    row.append(identity, role, status, revision, actions); return row;
  }));
  text("operators-page", `${page.page.returned} of ${page.page.total}`);
  for (const id of ["history-operator", "sessions-operator"]) {
    const filter = byId(id);
    const selected = filter.value;
    const options = [new Option("All", ""), ...page.items.map((item) => new Option(item.username, id === "history-operator" ? item.username : item.operator_id))];
    filter.replaceChildren(...options);
    filter.value = options.some((option) => option.value === selected) ? selected : "";
  }
}

function renderServiceAccounts(page) {
  const body = byId("service-accounts-table");

  body.replaceChildren(...page.items.map((item) => {
    const row = document.createElement("tr");

    const identity = document.createElement("td");
    const displayName = document.createElement("strong");
    displayName.textContent = item.display_name;

    const name = document.createElement("p");
    name.className = "muted";
    name.textContent = item.name;

    identity.append(displayName, name);

    const status = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = statusClass(item.status);
    badge.textContent = item.status;
    status.append(badge);

    const revision = document.createElement("td");
    revision.textContent = item.revision;

    const updated = document.createElement("td");
    updated.textContent = formatTime(item.updated_at);

    const actions = document.createElement("td");
    actions.className = "row-actions";

    actions.append(
      operationButton(
        "Tokens",
        () => openServiceAccountTokens(item),
        true,
      ),
    );

    if (
      item.status !== "revoked"
      && hasPermission(
        "control-plane.service-accounts.update",
      )
    ) {
      actions.append(
        operationButton(
          "Edit",
          () => updateServiceAccount(item),
          true,
        ),
      );
    }

    if (
      item.status === "active"
      && hasPermission(
        "control-plane.service-accounts.disable",
      )
    ) {
      actions.append(
        operationButton(
          "Disable",
          () => serviceAccountLifecycle(
            item,
            "disable",
          ),
          true,
        ),
      );
    }

    if (
      item.status === "disabled"
      && hasPermission(
        "control-plane.service-accounts.disable",
      )
    ) {
      actions.append(
        operationButton(
          "Enable",
          () => serviceAccountLifecycle(
            item,
            "enable",
          ),
          true,
        ),
      );
    }

    if (
      item.status !== "revoked"
      && hasPermission(
        "control-plane.service-accounts.revoke",
      )
    ) {
      actions.append(
        operationButton(
          "Revoke",
          () => serviceAccountLifecycle(
            item,
            "revoke",
          ),
          true,
        ),
      );
    }

    row.append(
      identity,
      status,
      revision,
      updated,
      actions,
    );

    return row;
  }));

  text(
    "service-accounts-page",
    `${page.page.returned} of ${page.page.total}`,
  );
}

function renderApiTokens(page) {
  const body = byId("api-tokens-table");

  body.replaceChildren(...page.items.map((item) => {
    const row = document.createElement("tr");

    const identity = document.createElement("td");
    const label = document.createElement("strong");
    label.textContent = item.label;

    const version = document.createElement("p");
    version.className = "muted";
    version.textContent = `Version ${item.token_version}`;

    identity.append(label, version);

    const scopes = document.createElement("td");
    scopes.textContent = item.scopes.join(", ") || "—";

    const resources = document.createElement("td");
    resources.textContent = item.resources.join(", ") || "—";

    const status = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = statusClass(item.status);
    badge.textContent = item.status;
    status.append(badge);

    const expires = document.createElement("td");
    expires.textContent = formatTime(item.expires_at);

    const revision = document.createElement("td");
    revision.textContent = item.revision;

    const actions = document.createElement("td");
    actions.className = "row-actions";

    if (
      item.status === "active"
      && hasPermission(
        "control-plane.api-tokens.rotate",
      )
    ) {
      actions.append(
        operationButton(
          "Rotate",
          () => rotateApiToken(item),
          true,
        ),
      );
    }

    if (
      item.status === "active"
      && hasPermission(
        "control-plane.api-tokens.revoke",
      )
    ) {
      actions.append(
        operationButton(
          "Revoke",
          () => revokeApiToken(item),
          true,
        ),
      );
    }

    if (!actions.children.length) {
      actions.textContent = "—";
    }

    row.append(
      identity,
      scopes,
      resources,
      status,
      expires,
      revision,
      actions,
    );

    return row;
  }));

  text(
    "api-tokens-page",
    `${page.page.returned} of ${page.page.total}`,
  );
}

function localDateTimeValue(value) {
  const offsetMilliseconds = (
    value.getTimezoneOffset() * 60 * 1000
  );

  return new Date(
    value.getTime() - offsetMilliseconds,
  ).toISOString().slice(0, 16);
}

function multilineFieldValues(elementId) {
  return Array.from(
    new Set(
      byId(elementId).value
        .split(/\r?\n/)
        .map((value) => value.trim())
        .filter(Boolean),
    ),
  );
}

function apiTokenRestrictionFromForm() {
  const allowedClientNetworks = multilineFieldValues(
    "api-token-networks",
  );

  const mutualTlsCertificateSha256 = byId(
    "api-token-mtls-sha256",
  ).value.trim().toLowerCase();

  if (
    mutualTlsCertificateSha256
    && !/^[0-9a-f]{64}$/.test(
      mutualTlsCertificateSha256,
    )
  ) {
    throw new Error(
      "mTLS certificate SHA-256 must contain 64 hexadecimal characters.",
    );
  }

  if (
    !allowedClientNetworks.length
    && !mutualTlsCertificateSha256
  ) {
    return null;
  }

  return {
    allowed_client_networks: allowedClientNetworks,
    mutual_tls_certificate_sha256: (
      mutualTlsCertificateSha256 || null
    ),
  };
}

function updateApiTokenIssueAvailability() {
  const selected = state.selectedServiceAccount;

  byId(
    "issue-api-token-submit",
  ).disabled = !(
    selected
    && selected.status === "active"
    && hasPermission(
      "control-plane.api-tokens.issue",
    )
  );
}

function clearServiceAccountSelection() {
  state.selectedServiceAccount = null;

  byId(
    "service-account-tokens-panel",
  ).classList.add("hidden");

  byId(
    "api-tokens-table",
  ).replaceChildren();

  text(
    "service-account-tokens-title",
    "API tokens",
  );

  text(
    "api-tokens-page",
    "",
  );

  text(
    "api-token-output",
    "A newly issued or rotated token appears here once. "
      + "Phoenix OS never stores its plaintext.",
  );
}

async function refreshSelectedServiceAccountTokens() {
  const selected = state.selectedServiceAccount;

  if (!selected) return;

  const page = await api(
    `/v1/control-plane/service-accounts/`
      + `${selected.service_account_id}/tokens?limit=200`,
  );

  renderApiTokens(page);
}

async function openServiceAccountTokens(account) {
  state.selectedServiceAccount = account;
  updateApiTokenIssueAvailability();

  text(
    "service-account-tokens-title",
    `API tokens · ${account.display_name}`,
  );

  text(
    "api-token-output",
    "A newly issued or rotated token appears here once. "
      + "Phoenix OS never stores its plaintext.",
  );

  const defaultExpiry = new Date(
    Date.now() + (24 * 60 * 60 * 1000),
  );

  byId("api-token-expires-at").value = (
    localDateTimeValue(defaultExpiry)
  );

  byId(
    "service-account-tokens-panel",
  ).classList.remove("hidden");

  try {
    await refreshSelectedServiceAccountTokens();
  } catch (error) {
    text(
      "api-token-output",
      `Token list unavailable: ${error.message}`,
    );

    if (error.message === "unauthorized") {
      await disconnect("Session rejected");
    }
  }
}

async function refreshServiceAccounts() {
  const panel = byId("service-accounts-panel");

  const canRead = (
    state.operatorMode
    && hasPermission(
      "control-plane.service-accounts.read",
    )
  );

  if (!canRead) {
    panel.classList.add("hidden");
    clearServiceAccountSelection();
    return;
  }

  try {
    const page = await api(
      "/v1/control-plane/service-accounts?limit=200",
    );

    panel.classList.remove("hidden");
    renderServiceAccounts(page);

    const canCreate = hasPermission(
      "control-plane.service-accounts.create",
    );

    byId(
      "create-service-account-submit",
    ).disabled = !canCreate;

    updateApiTokenIssueAvailability();

    text(
      "service-account-status",
      canCreate
        ? "Service-account administration ready."
        : "Service-account inventory loaded read-only.",
    );

    if (state.selectedServiceAccount) {
      const selected = page.items.find(
        (item) => (
          item.service_account_id
          === state.selectedServiceAccount.service_account_id
        ),
      );

      if (!selected) {
        clearServiceAccountSelection();
      } else {
        state.selectedServiceAccount = selected;
        updateApiTokenIssueAvailability();
        await refreshSelectedServiceAccountTokens();
      }
    }
  } catch (error) {
    if (error.message === "not_found") {
      panel.classList.add("hidden");
      clearServiceAccountSelection();
      return;
    }

    throw error;
  }
}

async function revokeApiToken(item) {
  if (
    item.status !== "active"
    || !hasPermission(
      "control-plane.api-tokens.revoke",
    )
  ) {
    text(
      "api-token-output",
      "API-token revocation is not permitted.",
    );

    return;
  }

  if (
    !window.confirm(
      `Permanently revoke API token ${item.label}?`,
    )
  ) {
    return;
  }

  try {
    text(
      "api-token-output",
      `Revoking API token ${item.label}...`,
    );

    const revoked = await operatorCommand(
      `/v1/control-plane/api-tokens/`
        + `${item.token_id}/revoke`,
      {
        expected_revision: item.revision,
      },
      "revoke-api-token",
    );

    text(
      "api-token-output",
      `${revoked.label}: ${revoked.status}`,
    );

    await refreshSelectedServiceAccountTokens();
  } catch (error) {
    text(
      "api-token-output",
      `API-token revocation failed: ${error.message}`,
    );
  }
}

async function rotateApiToken(item) {
  if (
    item.status !== "active"
    || !hasPermission(
      "control-plane.api-tokens.rotate",
    )
  ) {
    text(
      "api-token-output",
      "API-token rotation is not permitted.",
    );

    return;
  }

  const defaultExpiry = new Date(
    Date.now() + (24 * 60 * 60 * 1000),
  );

  const expiresValue = window.prompt(
    "New token expiration in local time",
    localDateTimeValue(defaultExpiry),
  );

  if (expiresValue === null) return;

  const expiresAt = new Date(
    expiresValue.trim(),
  );

  if (
    Number.isNaN(expiresAt.getTime())
    || expiresAt.getTime() <= Date.now()
  ) {
    text(
      "api-token-output",
      "Expiration must be a valid future date.",
    );

    return;
  }

  const overlapValue = window.prompt(
    "Old-token overlap in seconds. Use 0 for immediate revocation.",
    "0",
  );

  if (overlapValue === null) return;

  const normalizedOverlap = overlapValue.trim();

  if (!/^\d+$/.test(normalizedOverlap)) {
    text(
      "api-token-output",
      "Overlap must be a nonnegative integer.",
    );

    return;
  }

  const overlapSeconds = Number(
    normalizedOverlap,
  );

  if (
    !Number.isSafeInteger(overlapSeconds)
    || overlapSeconds < 0
  ) {
    text(
      "api-token-output",
      "Overlap is outside the supported numeric range.",
    );

    return;
  }

  if (
    !window.confirm(
      `Rotate API token ${item.label}?`,
    )
  ) {
    return;
  }

  try {
    text(
      "api-token-output",
      `Rotating API token ${item.label}...`,
    );

    const grant = await operatorCommand(
      `/v1/control-plane/api-tokens/`
        + `${item.token_id}/rotate`,
      {
        expected_revision: item.revision,
        expires_at: expiresAt.toISOString(),
        overlap_seconds: overlapSeconds,
      },
      "rotate-api-token",
    );

    text(
      "api-token-output",
      `Rotated token for ${grant.metadata.label}: ${grant.token}`,
    );

    await refreshSelectedServiceAccountTokens();
  } catch (error) {
    text(
      "api-token-output",
      `API-token rotation failed: ${error.message}`,
    );
  }
}

async function issueApiToken(event) {
  event.preventDefault();

  const selected = state.selectedServiceAccount;

  if (!selected) {
    text(
      "api-token-output",
      "Select a service account before issuing a token.",
    );

    return;
  }

  if (
    selected.status !== "active"
    || !hasPermission(
      "control-plane.api-tokens.issue",
    )
  ) {
    text(
      "api-token-output",
      "API-token issuance is not permitted.",
    );

    return;
  }

  const label = byId(
    "api-token-label",
  ).value.trim();

  const scopes = multilineFieldValues(
    "api-token-scopes",
  );

  const resources = multilineFieldValues(
    "api-token-resources",
  );

  const expiresValue = byId(
    "api-token-expires-at",
  ).value;

  if (
    !label
    || !scopes.length
    || !resources.length
    || !expiresValue
  ) {
    text(
      "api-token-output",
      "Label, expiration, scopes, and resources are required.",
    );

    return;
  }

  const expiresAt = new Date(expiresValue);

  if (
    Number.isNaN(expiresAt.getTime())
    || expiresAt.getTime() <= Date.now()
  ) {
    text(
      "api-token-output",
      "Expiration must be a valid future date.",
    );

    return;
  }

  try {
    const restriction = apiTokenRestrictionFromForm();

    const document = {
      label,
      scopes,
      resources,
      expires_at: expiresAt.toISOString(),
    };

    if (restriction) {
      document.restriction = restriction;
    }

    text(
      "api-token-output",
      "Issuing API token...",
    );

    const grant = await operatorCommand(
      `/v1/control-plane/service-accounts/`
        + `${selected.service_account_id}/issue-token`,
      document,
      "issue-api-token",
    );

    text(
      "api-token-output",
      `Token for ${grant.metadata.label}: ${grant.token}`,
    );

    byId(
      "issue-api-token-form",
    ).reset();

    const nextExpiry = new Date(
      Date.now() + (24 * 60 * 60 * 1000),
    );

    byId(
      "api-token-expires-at",
    ).value = localDateTimeValue(nextExpiry);

    await refreshSelectedServiceAccountTokens();
  } catch (error) {
    text(
      "api-token-output",
      `API-token issuance failed: ${error.message}`,
    );
  }
}

async function createServiceAccount(event) {
  event.preventDefault();

  const name = byId(
    "service-account-name",
  ).value.trim();

  const displayName = byId(
    "service-account-display-name",
  ).value.trim();

  if (!name || !displayName) {
    text(
      "service-account-status",
      "Name and display name are required.",
    );

    return;
  }

  try {
    text(
      "service-account-status",
      "Creating service account...",
    );

    const created = await operatorCommand(
      "/v1/control-plane/service-accounts",
      {
        name,
        display_name: displayName,
      },
    );

    byId(
      "create-service-account-form",
    ).reset();

    text(
      "service-account-status",
      `${created.display_name}: created`,
    );

    await refreshServiceAccounts();
  } catch (error) {
    text(
      "service-account-status",
      `Service-account creation failed: ${error.message}`,
    );
  }
}

async function updateServiceAccount(item) {
  const name = window.prompt(
    "Service-account name",
    item.name,
  );

  if (name === null) return;

  const displayName = window.prompt(
    "Service-account display name",
    item.display_name,
  );

  if (displayName === null) return;

  const normalizedName = name.trim();
  const normalizedDisplayName = displayName.trim();

  if (!normalizedName || !normalizedDisplayName) {
    text(
      "service-account-status",
      "Name and display name must not be blank.",
    );

    return;
  }

  try {
    text(
      "service-account-status",
      `${item.display_name}: updating`,
    );

    const updated = await operatorCommand(
      `/v1/control-plane/service-accounts/`
        + `${item.service_account_id}/update`,
      {
        expected_revision: item.revision,
        name: normalizedName,
        display_name: normalizedDisplayName,
      },
    );

    text(
      "service-account-status",
      `${updated.display_name}: updated`,
    );

    await refreshServiceAccounts();
  } catch (error) {
    text(
      "service-account-status",
      `Service-account update failed: ${error.message}`,
    );
  }
}

async function serviceAccountLifecycle(
  item,
  action,
) {
  if (
    action === "revoke"
    && !window.confirm(
      `Permanently revoke ${item.display_name}?`,
    )
  ) {
    return;
  }

  const stepUpAction = (
    action === "enable"
      ? "enable-service-account"
      : (
        action === "revoke"
          ? "revoke-service-account"
          : ""
      )
  );

  try {
    text(
      "service-account-status",
      `${item.display_name}: ${action} in progress`,
    );

    const updated = await operatorCommand(
      `/v1/control-plane/service-accounts/`
        + `${item.service_account_id}/${action}`,
      {
        expected_revision: item.revision,
      },
      stepUpAction,
    );

    text(
      "service-account-status",
      `${updated.display_name}: ${updated.status}`,
    );

    if (
      updated.status === "revoked"
      && state.selectedServiceAccount
      && (
        state.selectedServiceAccount.service_account_id
        === updated.service_account_id
      )
    ) {
      clearServiceAccountSelection();
    }

    await refreshServiceAccounts();
  } catch (error) {
    text(
      "service-account-status",
      `Service-account action failed: ${error.message}`,
    );
  }
}


function shortIdentity(value) {
  const normalized = String(value || "");
  return normalized.length > 12 ? `${normalized.slice(0, 12)}…` : normalized;
}

function webhookSubscriptionLabel(subscriptionId) {
  const subscription = state.webhookSubscriptions.get(subscriptionId);
  return subscription
    ? subscription.display_name
    : shortIdentity(subscriptionId);
}

function renderWebhookHealth(snapshot) {
  const subscriptions = snapshot.subscriptions;
  const deliveries = snapshot.deliveries;

  text(
    "webhooks-subscriptions-total",
    subscriptions.subscriptions,
  );
  text(
    "webhooks-summary",
    `${subscriptions.active} active · `
      + `${deliveries.pending + deliveries.in_flight + deliveries.retrying} queued · `
      + `${deliveries.dead_letter} dead-letter`,
  );
}

function renderWebhookSubscriptions(page) {
  state.webhookSubscriptions = new Map(
    page.items.map((item) => [item.id, item]),
  );

  const body = byId("webhook-subscriptions-table");

  body.replaceChildren(...page.items.map((item) => {
    const row = document.createElement("tr");

    const identity = document.createElement("td");
    const displayName = document.createElement("strong");
    displayName.textContent = item.display_name;
    const name = document.createElement("p");
    name.className = "muted";
    name.textContent = item.name;
    identity.append(displayName, name);

    const events = document.createElement("td");
    events.textContent = item.event_types.join(", ") || "—";

    const endpoint = document.createElement("td");
    const endpointHost = document.createElement("strong");
    endpointHost.textContent = (
      `${item.endpoint.scheme}://${item.endpoint.host}:${item.endpoint.port}`
    );
    const pathDigest = document.createElement("p");
    pathDigest.className = "muted";
    pathDigest.textContent = (
      `Path digest ${item.endpoint.path_sha256.slice(0, 12)}…`
    );
    endpoint.append(endpointHost, pathDigest);

    const status = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = statusClass(item.status);
    badge.textContent = item.status;
    status.append(badge);

    const signing = document.createElement("td");
    signing.textContent = (
      `${item.signing.scheme} · key v${item.signing.key_version}`
    );

    const revision = document.createElement("td");
    revision.textContent = item.revision;

    const actions = document.createElement("td");
    actions.className = "row-actions";

    if (
      item.status !== "revoked"
      && hasPermission("webhook.subscription.update")
    ) {
      actions.append(
        operationButton(
          "Edit",
          () => updateWebhookSubscription(item),
          true,
        ),
      );
    }

    if (
      item.status === "active"
      && hasPermission("webhook.subscription.disable")
    ) {
      actions.append(
        operationButton(
          "Disable",
          () => webhookSubscriptionLifecycle(item, "disable"),
          true,
        ),
      );
    }

    if (
      item.status === "disabled"
      && hasPermission("webhook.subscription.enable")
    ) {
      actions.append(
        operationButton(
          "Enable",
          () => webhookSubscriptionLifecycle(item, "enable"),
          true,
        ),
      );
    }

    if (
      item.status !== "revoked"
      && hasPermission("webhook.subscription.rotate")
    ) {
      actions.append(
        operationButton(
          "Rotate key",
          () => rotateWebhookSigningKey(item),
          true,
        ),
      );
    }

    if (
      item.status !== "revoked"
      && hasPermission("webhook.subscription.revoke")
    ) {
      actions.append(
        operationButton(
          "Revoke",
          () => webhookSubscriptionLifecycle(item, "revoke"),
          true,
        ),
      );
    }

    if (!actions.children.length) actions.textContent = "—";

    row.append(
      identity,
      events,
      endpoint,
      status,
      signing,
      revision,
      actions,
    );
    return row;
  }));

  text(
    "webhook-subscriptions-page",
    `${page.page.returned} of ${page.page.total}`,
  );
}

function renderWebhookDeliveries(page) {
  const body = byId("webhook-deliveries-table");

  body.replaceChildren(...page.items.map((item) => {
    const row = document.createElement("tr");

    const occurred = document.createElement("td");
    occurred.textContent = formatTime(item.occurred_at);

    const event = document.createElement("td");
    const eventName = document.createElement("strong");
    eventName.textContent = item.event_type;
    const deliveryId = document.createElement("p");
    deliveryId.className = "muted";
    deliveryId.textContent = shortIdentity(item.id);
    event.append(eventName, deliveryId);

    const subscription = document.createElement("td");
    subscription.textContent = webhookSubscriptionLabel(
      item.subscription_id,
    );

    const status = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = statusClass(item.status);
    badge.textContent = item.status;
    status.append(badge);

    const attempts = document.createElement("td");
    attempts.textContent = item.attempts.length;

    const nextAttempt = document.createElement("td");
    nextAttempt.textContent = formatTime(item.next_attempt_at);

    const actions = document.createElement("td");
    actions.className = "row-actions";

    if (
      item.redrive_eligible
      && hasPermission("webhook.delivery.redrive")
    ) {
      actions.append(
        operationButton(
          "Redrive",
          () => redriveWebhookDelivery(item),
          true,
        ),
      );
    } else {
      actions.textContent = "—";
    }

    row.append(
      occurred,
      event,
      subscription,
      status,
      attempts,
      nextAttempt,
      actions,
    );
    return row;
  }));

  text(
    "webhook-deliveries-page",
    `${page.page.returned} of ${page.page.total}`,
  );
}

function webhookNumericValue(elementId, label, options = {}) {
  const value = Number(byId(elementId).value);
  const minimum = options.minimum ?? 0;

  if (
    !Number.isFinite(value)
    || value < minimum
    || (
      options.integer
      && !Number.isSafeInteger(value)
    )
  ) {
    throw new Error(`${label} is outside the supported range.`);
  }

  return value;
}

async function createWebhookSubscription(event) {
  event.preventDefault();

  const eventTypes = multilineFieldValues(
    "webhook-event-types",
  );
  const name = byId("webhook-name").value.trim();
  const displayName = byId(
    "webhook-display-name",
  ).value.trim();
  const endpointUrl = byId(
    "webhook-endpoint-url",
  ).value.trim();
  const egressPolicy = byId(
    "webhook-egress-policy",
  ).value.trim();
  const secretName = byId(
    "webhook-secret-name",
  ).value.trim();
  const secretNamespace = byId(
    "webhook-secret-namespace",
  ).value.trim();

  if (
    !name
    || !displayName
    || !eventTypes.length
    || !endpointUrl
    || !egressPolicy
    || !secretName
    || !secretNamespace
  ) {
    text(
      "webhook-subscription-status",
      "Every subscription identity, event, endpoint, policy, and signing field is required.",
    );
    return;
  }

  try {
    const document = {
      name,
      display_name: displayName,
      event_types: eventTypes,
      endpoint: {
        url: endpointUrl,
        allow_insecure_loopback: byId(
          "webhook-loopback-development",
        ).checked,
      },
      signing: {
        secret_name: secretName,
        secret_namespace: secretNamespace,
        secret_version: webhookNumericValue(
          "webhook-secret-version",
          "Secret version",
          { minimum: 1, integer: true },
        ),
        lease_ttl_seconds: webhookNumericValue(
          "webhook-lease-ttl",
          "Signing lease",
          { minimum: 0.001 },
        ),
      },
      egress_policy: egressPolicy,
      retry: {
        max_attempts: webhookNumericValue(
          "webhook-max-attempts",
          "Maximum attempts",
          { minimum: 1, integer: true },
        ),
        initial_delay_seconds: webhookNumericValue(
          "webhook-initial-delay",
          "Initial retry delay",
        ),
        max_delay_seconds: webhookNumericValue(
          "webhook-max-delay",
          "Maximum retry delay",
        ),
      },
    };

    text(
      "webhook-subscription-status",
      "Creating webhook subscription...",
    );

    const created = await operatorCommand(
      "/v1/control-plane/webhooks/subscriptions",
      document,
      "create-webhook-subscription",
    );

    text(
      "webhook-subscription-status",
      `${created.display_name}: created`,
    );

    byId(
      "create-webhook-subscription-form",
    ).reset();

    await refreshWebhooks();
  } catch (error) {
    text(
      "webhook-subscription-status",
      `Webhook subscription creation failed: ${error.message}`,
    );
  }
}

async function updateWebhookSubscription(item) {
  const name = window.prompt(
    "Subscription name",
    item.name,
  );
  if (name === null) return;

  const displayName = window.prompt(
    "Subscription display name",
    item.display_name,
  );
  if (displayName === null) return;

  const events = window.prompt(
    "Event types separated by commas",
    item.event_types.join(", "),
  );
  if (events === null) return;

  const egressPolicy = window.prompt(
    "Egress policy",
    item.egress_policy,
  );
  if (egressPolicy === null) return;

  const endpointUrl = window.prompt(
    "New endpoint URL. Leave blank to retain the protected current path.",
    "",
  );
  if (endpointUrl === null) return;

  const eventTypes = Array.from(
    new Set(
      events
        .split(",")
        .map((value) => value.trim())
        .filter(Boolean),
    ),
  );

  if (
    !name.trim()
    || !displayName.trim()
    || !eventTypes.length
    || !egressPolicy.trim()
  ) {
    text(
      "webhook-subscription-status",
      "Name, display name, event types, and egress policy must not be blank.",
    );
    return;
  }

  const document = {
    expected_revision: item.revision,
    name: name.trim(),
    display_name: displayName.trim(),
    event_types: eventTypes,
    egress_policy: egressPolicy.trim(),
    retry: item.retry,
    resource_filters: item.resource_filters,
  };

  if (endpointUrl.trim()) {
    document.endpoint = {
      url: endpointUrl.trim(),
      allow_insecure_loopback: (
        item.endpoint.loopback_development
      ),
    };
  }

  try {
    const updated = await operatorCommand(
      `/v1/control-plane/webhooks/subscriptions/${item.id}/update`,
      document,
      "update-webhook-subscription",
    );

    text(
      "webhook-subscription-status",
      `${updated.display_name}: updated`,
    );

    await refreshWebhooks();
  } catch (error) {
    text(
      "webhook-subscription-status",
      `Webhook subscription update failed: ${error.message}`,
    );
  }
}

async function webhookSubscriptionLifecycle(item, action) {
  if (
    action === "revoke"
    && !window.confirm(
      `Permanently revoke ${item.display_name}?`,
    )
  ) {
    return;
  }

  const stepUpAction = {
    enable: "enable-webhook-subscription",
    revoke: "revoke-webhook-subscription",
  }[action] || "";

  try {
    const updated = await operatorCommand(
      `/v1/control-plane/webhooks/subscriptions/${item.id}/${action}`,
      {
        expected_revision: item.revision,
      },
      stepUpAction,
    );

    text(
      "webhook-subscription-status",
      `${updated.display_name}: ${updated.status}`,
    );

    await refreshWebhooks();
  } catch (error) {
    text(
      "webhook-subscription-status",
      `Webhook subscription action failed: ${error.message}`,
    );
  }
}

async function rotateWebhookSigningKey(item) {
  const secretName = window.prompt(
    "New signing secret name. The current reference is intentionally hidden.",
    "",
  );
  if (secretName === null) return;

  const secretNamespace = window.prompt(
    "New signing secret namespace",
    "webhooks",
  );
  if (secretNamespace === null) return;

  const secretVersionValue = window.prompt(
    "New signing secret version",
    String(item.signing.key_version + 1),
  );
  if (secretVersionValue === null) return;

  const leaseTtlValue = window.prompt(
    "Signing lease TTL in seconds",
    String(item.signing.lease_ttl_seconds),
  );
  if (leaseTtlValue === null) return;

  const secretVersion = Number(secretVersionValue.trim());
  const leaseTtlSeconds = Number(leaseTtlValue.trim());

  if (
    !secretName.trim()
    || !secretNamespace.trim()
    || !Number.isSafeInteger(secretVersion)
    || secretVersion <= 0
    || !Number.isFinite(leaseTtlSeconds)
    || leaseTtlSeconds <= 0
  ) {
    text(
      "webhook-subscription-status",
      "Signing-key rotation fields are invalid.",
    );
    return;
  }

  if (
    !window.confirm(
      `Rotate the signing key for ${item.display_name}?`,
    )
  ) {
    return;
  }

  try {
    const updated = await operatorCommand(
      `/v1/control-plane/webhooks/subscriptions/`
        + `${item.id}/rotate-signing-key`,
      {
        expected_revision: item.revision,
        secret_name: secretName.trim(),
        secret_namespace: secretNamespace.trim(),
        secret_version: secretVersion,
        lease_ttl_seconds: leaseTtlSeconds,
      },
      "rotate-webhook-signing-key",
    );

    text(
      "webhook-subscription-status",
      `${updated.display_name}: signing key v${updated.signing.key_version}`,
    );

    await refreshWebhooks();
  } catch (error) {
    text(
      "webhook-subscription-status",
      `Webhook signing-key rotation failed: ${error.message}`,
    );
  }
}

async function redriveWebhookDelivery(item) {
  if (
    !item.redrive_eligible
    || !hasPermission("webhook.delivery.redrive")
  ) {
    text(
      "webhook-delivery-status",
      "This delivery is not eligible for redrive.",
    );
    return;
  }

  if (
    !window.confirm(
      `Redrive delivery ${shortIdentity(item.id)}?`,
    )
  ) {
    return;
  }

  try {
    const result = await operatorCommand(
      `/v1/control-plane/webhooks/deliveries/${item.id}/redrive`,
      {},
      "redrive-webhook-delivery",
    );

    text(
      "webhook-delivery-status",
      `Delivery ${shortIdentity(result.delivery_id)}: ${result.status}`,
    );

    await refreshWebhooks();
  } catch (error) {
    text(
      "webhook-delivery-status",
      `Webhook delivery redrive failed: ${error.message}`,
    );
  }
}

async function refreshWebhooks() {
  const healthCard = byId("webhooks-card");
  const subscriptionsPanel = byId(
    "webhook-subscriptions-panel",
  );
  const deliveriesPanel = byId(
    "webhook-deliveries-panel",
  );

  const canReadHealth = (
    state.operatorMode
    && hasPermission("webhook.health.read")
  );
  const canReadSubscriptions = (
    state.operatorMode
    && hasPermission("webhook.subscription.read")
  );
  const canReadDeliveries = (
    state.operatorMode
    && hasPermission("webhook.delivery.read")
  );

  healthCard.classList.toggle("hidden", !canReadHealth);
  subscriptionsPanel.classList.toggle(
    "hidden",
    !canReadSubscriptions,
  );
  deliveriesPanel.classList.toggle(
    "hidden",
    !canReadDeliveries,
  );

  byId(
    "create-webhook-subscription-form",
  ).classList.toggle(
    "hidden",
    !hasPermission("webhook.subscription.create"),
  );

  if (!canReadSubscriptions) {
    state.webhookSubscriptions = new Map();
    byId(
      "webhook-subscriptions-table",
    ).replaceChildren();
  }

  if (!canReadDeliveries) {
    byId(
      "webhook-deliveries-table",
    ).replaceChildren();
  }

  if (canReadHealth) {
    try {
      renderWebhookHealth(
        await api("/v1/control-plane/webhooks/health"),
      );
    } catch (error) {
      if (error.message === "unauthorized") throw error;
      text(
        "webhooks-summary",
        `Webhook health unavailable: ${error.message}`,
      );
    }
  }

  if (canReadSubscriptions) {
    try {
      renderWebhookSubscriptions(
        await api(
          "/v1/control-plane/webhooks/subscriptions?limit=200",
        ),
      );
      text(
        "webhook-subscription-status",
        hasPermission("webhook.subscription.create")
          ? "Webhook subscription administration ready."
          : "Webhook subscription inventory loaded read-only.",
      );
    } catch (error) {
      if (error.message === "unauthorized") throw error;
      text(
        "webhook-subscription-status",
        `Webhook subscriptions unavailable: ${error.message}`,
      );
    }
  }

  if (canReadDeliveries) {
    try {
      renderWebhookDeliveries(
        await api(
          "/v1/control-plane/webhooks/deliveries?limit=200",
        ),
      );
      text(
        "webhook-delivery-status",
        "Bounded body-free delivery history loaded.",
      );
    } catch (error) {
      if (error.message === "unauthorized") throw error;
      text(
        "webhook-delivery-status",
        `Webhook deliveries unavailable: ${error.message}`,
      );
    }
  }
}

function renderOperations(payload) {
  state.operations = payload.actions || {};
  const any = Object.values(state.operations).some(Boolean);
  byId("operations-panel").classList.toggle("hidden", !any);
  byId("create-job-submit").disabled = !state.operations["job.create"];
}

async function refresh() {
  try {
    if (state.operatorMode && !state.me) {
      state.me = await api("/v1/control-plane/operator/me");
      text("operator-identity", state.me.username);
    } else if (!state.operatorMode) text("operator-identity", "Legacy administrator");
    const historyOperator = byId("history-operator").value;
    const historyPath = `/v1/control-plane/commands/history?limit=20${historyOperator ? `&operator=${encodeURIComponent(historyOperator)}` : ""}`;
    const [snapshot, jobs, workflows, capabilities, plugins, audit, operations, history] = await Promise.all([
      api("/v1/control-plane/snapshot"), api("/v1/control-plane/jobs?limit=20"), api("/v1/control-plane/workflows?limit=20"),
      api("/v1/control-plane/capabilities?limit=50"), api("/v1/control-plane/plugins?limit=50"), api("/v1/control-plane/audit"),
      api("/v1/control-plane/operations"), api(historyPath),
    ]);
    renderOperations(operations); renderSnapshot(snapshot); renderJobs(jobs); renderWorkflows(workflows); renderHistory(history);
    renderStack("capabilities-list", capabilities.items, (item) => [item.name, `${item.risk} risk · ${item.required_permissions.length} permissions`, null]);
    renderStack("plugins-list", plugins.items, (item) => [item.name, `${item.version} · ${item.exports.capabilities} capabilities`, item.status]);
    text("audit-total", audit.available ? audit.records : 0);
    text("audit-summary", audit.available ? `${audit.signed_records} signed · ${audit.verification_failures} verification failures` : "Unavailable");
    const canReadOperators = state.me && state.me.permissions.includes("control-plane.operators.read");
    const canReadSessions = state.me && state.me.permissions.includes("control-plane.operator-sessions.read");
    byId("operators-panel").classList.toggle("hidden", !canReadOperators);
    byId("sessions-panel").classList.toggle("hidden", !canReadSessions);
    if (canReadOperators) {
      const operators = await api("/v1/control-plane/operators?limit=200");
      renderOperators(operators);
      byId("create-operator-submit").disabled = !state.me.permissions.includes("control-plane.operators.create");
    }
    if (canReadSessions) {
      const operatorId = byId("sessions-operator").value;
      const sessionStatus = byId("sessions-status").value;
      const sessionPath = `/v1/control-plane/operator-sessions?limit=50${operatorId ? `&operator_id=${encodeURIComponent(operatorId)}` : ""}${sessionStatus ? `&status=${encodeURIComponent(sessionStatus)}` : ""}`;
      renderSessions(await api(sessionPath));
    }

    await refreshServiceAccounts();
    await refreshWebhooks();

    setConnected(
      true,
      state.me
        ? `Connected as ${state.me.username}`
        : "Connected",
    );
  } catch (error) {
    if (error.message === "unauthorized") disconnect("Session rejected");
    else setConnected(state.connected, "API unavailable");
  }
}

function appendEvents(batch) {
  if (batch.gap) text("event-status", `${batch.dropped} events dropped before this cursor`);
  else text("event-status", batch.timed_out ? "Waiting" : `Cursor ${batch.cursor}`);
  const list = byId("events-list");
  for (const event of batch.items) {
    const li = document.createElement("li");
    const time = document.createElement("time"); time.dateTime = event.occurred_at; time.textContent = formatTime(event.occurred_at);
    const name = document.createElement("strong"); name.textContent = event.name;
    const source = document.createElement("p"); source.className = "muted"; source.textContent = event.source;
    li.append(time, name, source); list.prepend(li);
  }
  while (list.children.length > 100) list.lastElementChild.remove();
  state.cursor = batch.cursor;
}

async function eventLoop() {
  while (state.connected) {
    try {
      const batch = await api(`/v1/control-plane/events?after=${state.cursor}&limit=50&wait=3`);
      appendEvents(batch);
      if (batch.items.length) await refresh();
    } catch (error) {
      if (!state.connected) return;
      text("event-status", error.message === "unauthorized" ? "Authorization lost" : "Reconnecting");
      await new Promise((resolve) => setTimeout(resolve, 1500));
    }
  }
}

function showCommand(payload) { text("command-status", `${payload.status}: ${payload.result_code || "completed"}`); }

async function createJob(event) {
  event.preventDefault();
  try {
    const argumentsValue = JSON.parse(byId("job-arguments").value || "{}");
    if (!argumentsValue || Array.isArray(argumentsValue) || typeof argumentsValue !== "object") throw new Error("arguments_object");
    text("command-status", "Creating job…");
    const payload = await command("/v1/control-plane/commands/jobs/create", { capability: byId("job-capability").value.trim(), run_at: new Date().toISOString(), arguments: argumentsValue });
    showCommand(payload); await refresh();
  } catch (error) { text("command-status", error.message === "arguments_object" ? "Arguments must be a JSON object" : `Command failed: ${error.message}`); }
}

async function retryJob(jobId) {
  try { text("command-status", "Retrying dead-letter job…"); showCommand(await command("/v1/control-plane/commands/jobs/retry-dead-letter", { job_id: jobId })); await refresh(); }
  catch (error) { text("command-status", `Command failed: ${error.message}`); }
}

async function destructiveCommand(kind, id) {
  const key = newKey(); const isJob = kind === "job"; const field = isJob ? "job_id" : "workflow_id"; const base = isJob ? "jobs" : "workflows";
  const challenge = await command(`/v1/control-plane/commands/${base}/cancel/confirmation`, { [field]: id }, key);
  if (!window.confirm(`Confirm cancellation of ${kind} ${id}?`)) { text("command-status", "Cancellation aborted"); return; }
  showCommand(await command(`/v1/control-plane/commands/${base}/cancel`, { [field]: id, command_id: challenge.command_id }, key, challenge.confirmation_proof));
  await refresh();
}

async function cancelJob(jobId) { try { await destructiveCommand("job", jobId); } catch (error) { text("command-status", `Command failed: ${error.message}`); } }
async function cancelWorkflow(workflowId) { try { await destructiveCommand("workflow", workflowId); } catch (error) { text("command-status", `Command failed: ${error.message}`); } }

async function createOperator(event) {
  event.preventDefault();
  try {
    const role = byId("operator-role").value;
    const payload = await operatorCommand("/v1/control-plane/operators", {
      username: byId("operator-username").value.trim(), display_name: byId("operator-display-name").value.trim(), role,
    }, role === "maintainer" ? "create-maintainer" : "");
    text("operator-token-output", `Credential for ${payload.username}: ${payload.token}`); event.target.reset(); await refresh();
  } catch (error) { text("operator-token-output", `Operator creation failed: ${error.message}`); }
}

async function updateOperator(item) {
  const displayName = window.prompt("Operator display name", item.display_name); if (displayName === null) return;
  const role = window.prompt("Role: viewer, operator, or maintainer", item.role); if (role === null) return;
  const normalizedRole = role.trim().toLowerCase();
  if (!["viewer", "operator", "maintainer"].includes(normalizedRole)) { text("operator-token-output", "Operator update failed: invalid role"); return; }
  try {
    await operatorCommand(`/v1/control-plane/operators/${item.operator_id}/update`, {
      expected_revision: item.revision, display_name: displayName.trim(), role: normalizedRole, additional_permissions: item.additional_permissions,
    }, "update-access");
    text("operator-token-output", `${item.username}: profile updated`); await refresh();
  } catch (error) { text("operator-token-output", `Operator update failed: ${error.message}`); }
}

async function operatorLifecycle(item, action) {
  if (action === "revoke" && !window.confirm(`Permanently revoke ${item.username}?`)) return;
  try {
    await operatorCommand(`/v1/control-plane/operators/${item.operator_id}/${action}`, { expected_revision: item.revision }, action === "revoke" ? "revoke-operator" : "");
    text("operator-token-output", `${item.username}: ${action} completed`); await refresh();
  } catch (error) { text("operator-token-output", `Operator action failed: ${error.message}`); }
}

async function rotateOperator(item) {
  if (!window.confirm(`Rotate the credential for ${item.username}? Existing sessions will be revoked.`)) return;
  try {
    const payload = await operatorCommand(`/v1/control-plane/operators/${item.operator_id}/rotate`, { expected_revision: item.revision }, "rotate-credential");
    text("operator-token-output", `New credential for ${payload.username}: ${payload.token}`); await refresh();
  } catch (error) { text("operator-token-output", `Credential rotation failed: ${error.message}`); }
}

async function revokeOperatorSessions(item) {
  if (!window.confirm(`End every active session for ${item.username}?`)) return;
  try {
    const payload = await operatorCommand(`/v1/control-plane/operators/${item.operator_id}/revoke-sessions`, { expected_revision: item.revision }, "revoke-operator-sessions");
    text("operator-token-output", `${item.username}: ${payload.revoked} sessions ended`); await refresh();
  } catch (error) { text("operator-token-output", `Session revocation failed: ${error.message}`); }
}

async function revokeSession(sessionId) {
  if (!window.confirm(`End session ${sessionId}?`)) return;
  try { await operatorCommand(`/v1/control-plane/operator-sessions/${sessionId}/revoke`, {}); await refresh(); }
  catch (error) { text("operator-token-output", `Session revocation failed: ${error.message}`); }
}

async function connect(credential) {
  const supplied = credential.trim(); text("login-error", "");
  try {
    const exchange = await exchangeOperatorCredential(supplied);
    if (exchange) {
      state.operatorMode = true; state.legacyToken = "";
      state.me = { username: exchange.username, permissions: [] };
    } else {
      state.operatorMode = false; state.legacyToken = supplied; state.me = null;
      await issueLegacyCsrf();
    }
    await api("/v1/control-plane/health");
    if (state.operatorMode) state.me = await api("/v1/control-plane/operator/me");
  } catch (error) {
    state.legacyToken = ""; state.csrf = ""; state.me = null; state.operatorMode = false;
    text("login-error", error.message === "unauthorized" ? "The operator credential was rejected." : "The local API is unavailable."); return;
  }
  byId("token").value = "";
  setConnected(true, "Connected"); await refresh();
  state.refreshTimer = window.setInterval(refresh, 5000); state.eventLoop = eventLoop();
}

async function disconnect(reason = "Disconnected") {
  state.connected = false;
  if (state.refreshTimer) window.clearInterval(state.refreshTimer);
  if (state.operatorMode) {
    try {
      await request("/v1/control-plane/operator/logout", {
        method: "POST",
        headers: { "X-Phoenix-CSRF": state.csrf },
      });
    } catch (_) { /* cookie cleanup is also returned on rejected sessions */ }
  }
  clearServiceAccountSelection();
  byId("service-accounts-panel").classList.add("hidden");
  byId("webhooks-card").classList.add("hidden");
  byId("webhook-subscriptions-panel").classList.add("hidden");
  byId("webhook-deliveries-panel").classList.add("hidden");
  byId("webhook-subscriptions-table").replaceChildren();
  byId("webhook-deliveries-table").replaceChildren();
  state.webhookSubscriptions = new Map();

  state.refreshTimer = null; state.cursor = 0; state.legacyToken = ""; state.csrf = ""; state.operations = {}; state.me = null; state.operatorMode = false;
  byId("token").value = ""; text("operator-identity", "Anonymous"); setConnected(false, reason);
}

byId("login-form").addEventListener("submit", (event) => { event.preventDefault(); connect(byId("token").value); });
byId("create-job-form").addEventListener("submit", createJob);
byId("create-operator-form").addEventListener("submit", createOperator);

byId("create-webhook-subscription-form").addEventListener(
  "submit",
  createWebhookSubscription,
);

byId("create-service-account-form").addEventListener(
  "submit",
  createServiceAccount,
);

byId("issue-api-token-form").addEventListener(
  "submit",
  issueApiToken,
);

byId("close-service-account-tokens").addEventListener(
  "click",
  clearServiceAccountSelection,
);

byId("history-operator").addEventListener("change", refresh);
byId("sessions-operator").addEventListener("change", refresh);
byId("sessions-status").addEventListener("change", refresh);
byId("refresh").addEventListener("click", refresh);
byId("disconnect").addEventListener("click", () => disconnect());
window.addEventListener("pagehide", () => { state.connected = false; });

setConnected(false, "Disconnected");
