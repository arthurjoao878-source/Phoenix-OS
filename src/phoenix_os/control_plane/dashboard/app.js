"use strict";

const state = {
  token: sessionStorage.getItem("phoenix.controlPlane.token") || "",
  csrf: sessionStorage.getItem("phoenix.controlPlane.csrf") || "",
  cursor: 0,
  connected: false,
  refreshTimer: null,
  eventLoop: null,
  operations: {},
  me: null,
  operatorMode: sessionStorage.getItem("phoenix.controlPlane.operatorMode") === "1",
  temporarySession: sessionStorage.getItem("phoenix.controlPlane.temporarySession") === "1",
};

const byId = (id) => document.getElementById(id);
const text = (id, value) => { byId(id).textContent = String(value); };
const formatTime = (value) => value ? new Date(value).toLocaleString() : "—";
const statusClass = (value) => `status status-${String(value).replaceAll(" ", "_")}`;
const newKey = () => `dashboard-${crypto.randomUUID()}`;

async function request(path, options = {}) {
  const headers = new Headers(options.headers || {});
  headers.set("Authorization", `Bearer ${state.token}`);
  headers.set("Accept", "application/json");
  const response = await fetch(path, { ...options, headers, cache: "no-store" });
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
  });
  const payload = await response.json();
  if (response.ok) return payload;
  if ([404, 405].includes(response.status) || payload.error === "not_found" || payload.error === "method_not_allowed") return null;
  const error = new Error(response.status === 401 ? "unauthorized" : (payload.error || `http_${response.status}`));
  throw error;
}

async function operatorCommand(path, body) {
  if (!state.csrf) await issueCsrf();
  const headers = new Headers({
    "Content-Type": "application/json",
    "X-Phoenix-CSRF": state.csrf,
  });
  return request(path, { method: "POST", headers, body: JSON.stringify(body) });
}

async function issueCsrf() {
  const payload = await request("/v1/control-plane/csrf", { method: "POST" });
  state.csrf = payload.csrf_token;
  sessionStorage.setItem("phoenix.controlPlane.csrf", state.csrf);
}

async function command(path, body, key = newKey(), confirmation = "") {
  if (!state.csrf) await issueCsrf();
  const headers = new Headers({
    "Content-Type": "application/json",
    "Idempotency-Key": key,
    "X-Phoenix-CSRF": state.csrf,
  });
  if (confirmation) headers.set("X-Phoenix-Confirmation", confirmation);
  try {
    return await request(path, { method: "POST", headers, body: JSON.stringify(body) });
  } catch (error) {
    if (error.message === "request_rejected") {
      await issueCsrf();
    }
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
    const counts = workflow.steps.reduce((result, step) => {
      result[step.status] = (result[step.status] || 0) + 1;
      return result;
    }, {});
    steps.textContent = Object.entries(counts).map(([key, count]) => `${key}: ${count}`).join(" · ") || "0 total";
    const actions = document.createElement("td");
    if (["pending", "running"].includes(workflow.status) && state.operations["workflow.cancel"]) {
      actions.append(operationButton("Cancel", () => cancelWorkflow(workflow.id), true));
    } else actions.textContent = "—";
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
  body.replaceChildren(...page.items.map((commandItem) => {
    const row = document.createElement("tr");
    const requested = document.createElement("td"); requested.textContent = formatTime(commandItem.requested_at);
    const action = document.createElement("td"); action.textContent = commandItem.action;
    const target = document.createElement("td"); target.textContent = commandItem.target;
    const status = document.createElement("td");
    const badge = document.createElement("span"); badge.className = statusClass(commandItem.status); badge.textContent = commandItem.status; status.append(badge);
    const result = document.createElement("td"); result.textContent = commandItem.result_code || "—";
    const principal = document.createElement("td"); principal.textContent = commandItem.principal;
    row.append(requested, action, target, status, result, principal);
    return row;
  }));
  text("commands-page", `${page.page.returned} of ${page.page.total}`);
}

function renderOperators(page) {
  const body = byId("operators-table");
  const can = (permission) => state.me && state.me.permissions.includes(permission);
  body.replaceChildren(...page.items.map((operatorItem) => {
    const row = document.createElement("tr");
    const identity = document.createElement("td");
    const strong = document.createElement("strong"); strong.textContent = operatorItem.display_name;
    const username = document.createElement("p"); username.className = "muted"; username.textContent = operatorItem.username;
    identity.append(strong, username);
    const role = document.createElement("td"); role.textContent = operatorItem.role;
    const status = document.createElement("td");
    const badge = document.createElement("span"); badge.className = statusClass(operatorItem.status); badge.textContent = operatorItem.status; status.append(badge);
    const revision = document.createElement("td"); revision.textContent = operatorItem.revision;
    const actions = document.createElement("td"); actions.className = "row-actions";
    if (operatorItem.status !== "revoked" && can("control-plane.operators.update")) {
      actions.append(operationButton("Edit", () => updateOperator(operatorItem), true));
    }
    if (operatorItem.status === "active" && can("control-plane.operators.disable")) {
      actions.append(operationButton("Disable", () => operatorLifecycle(operatorItem, "disable"), true));
    }
    if (operatorItem.status === "disabled" && can("control-plane.operators.disable")) {
      actions.append(operationButton("Reactivate", () => operatorLifecycle(operatorItem, "reactivate"), true));
    }
    if (operatorItem.status !== "revoked" && can("control-plane.operators.rotate")) {
      actions.append(operationButton("Rotate", () => rotateOperator(operatorItem), true));
    }
    if (operatorItem.status !== "revoked" && can("control-plane.operators.revoke")) {
      actions.append(operationButton("Revoke", () => operatorLifecycle(operatorItem, "revoke"), true));
    }
    if (!actions.children.length) actions.textContent = "—";
    row.append(identity, role, status, revision, actions);
    return row;
  }));
  text("operators-page", `${page.page.returned} of ${page.page.total}`);
  const filter = byId("history-operator");
  const selected = filter.value;
  const options = [new Option("All", ""), ...page.items.map((item) => new Option(item.username, item.username))];
  filter.replaceChildren(...options);
  filter.value = options.some((item) => item.value === selected) ? selected : "";
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
    } else if (!state.operatorMode) {
      text("operator-identity", "Legacy administrator");
    }
    const historyOperator = byId("history-operator").value;
    const historyPath = `/v1/control-plane/commands/history?limit=20${historyOperator ? `&operator=${encodeURIComponent(historyOperator)}` : ""}`;
    const baseRequests = [
      api("/v1/control-plane/snapshot"),
      api("/v1/control-plane/jobs?limit=20"),
      api("/v1/control-plane/workflows?limit=20"),
      api("/v1/control-plane/capabilities?limit=50"),
      api("/v1/control-plane/plugins?limit=50"),
      api("/v1/control-plane/audit"),
      api("/v1/control-plane/operations"),
      api(historyPath),
    ];
    const [snapshot, jobs, workflows, capabilities, plugins, audit, operations, history] = await Promise.all(baseRequests);
    renderOperations(operations); renderSnapshot(snapshot); renderJobs(jobs); renderWorkflows(workflows); renderHistory(history);
    renderStack("capabilities-list", capabilities.items, (item) => [item.name, `${item.risk} risk · ${item.required_permissions.length} permissions`, null]);
    renderStack("plugins-list", plugins.items, (item) => [item.name, `${item.version} · ${item.exports.capabilities} capabilities`, item.status]);
    text("audit-total", audit.available ? audit.records : 0);
    text("audit-summary", audit.available ? `${audit.signed_records} signed · ${audit.verification_failures} verification failures` : "Unavailable");
    const canReadOperators = state.me && state.me.permissions.includes("control-plane.operators.read");
    byId("operators-panel").classList.toggle("hidden", !canReadOperators);
    if (canReadOperators) {
      const operators = await api("/v1/control-plane/operators?limit=200");
      renderOperators(operators);
      byId("create-operator-submit").disabled = !state.me.permissions.includes("control-plane.operators.create");
    }
    setConnected(true, state.me ? `Connected as ${state.me.username}` : "Connected");
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

function showCommand(payload) {
  text("command-status", `${payload.status}: ${payload.result_code || "completed"}`);
}

async function createJob(event) {
  event.preventDefault();
  try {
    const argumentsValue = JSON.parse(byId("job-arguments").value || "{}");
    if (!argumentsValue || Array.isArray(argumentsValue) || typeof argumentsValue !== "object") throw new Error("arguments_object");
    text("command-status", "Creating job…");
    const payload = await command("/v1/control-plane/commands/jobs/create", {
      capability: byId("job-capability").value.trim(),
      run_at: new Date().toISOString(),
      arguments: argumentsValue,
    });
    showCommand(payload); await refresh();
  } catch (error) {
    text("command-status", error.message === "arguments_object" ? "Arguments must be a JSON object" : `Command failed: ${error.message}`);
  }
}

async function retryJob(jobId) {
  try {
    text("command-status", "Retrying dead-letter job…");
    const payload = await command("/v1/control-plane/commands/jobs/retry-dead-letter", { job_id: jobId });
    showCommand(payload); await refresh();
  } catch (error) { text("command-status", `Command failed: ${error.message}`); }
}

async function destructiveCommand(kind, id) {
  const key = newKey();
  const isJob = kind === "job";
  const field = isJob ? "job_id" : "workflow_id";
  const base = isJob ? "jobs" : "workflows";
  const challenge = await command(`/v1/control-plane/commands/${base}/cancel/confirmation`, { [field]: id }, key);
  if (!window.confirm(`Confirm cancellation of ${kind} ${id}?`)) {
    text("command-status", "Cancellation aborted"); return;
  }
  const payload = await command(
    `/v1/control-plane/commands/${base}/cancel`,
    { [field]: id, command_id: challenge.command_id },
    key,
    challenge.confirmation_proof,
  );
  showCommand(payload); await refresh();
}

async function cancelJob(jobId) {
  try { await destructiveCommand("job", jobId); }
  catch (error) { text("command-status", `Command failed: ${error.message}`); }
}

async function cancelWorkflow(workflowId) {
  try { await destructiveCommand("workflow", workflowId); }
  catch (error) { text("command-status", `Command failed: ${error.message}`); }
}

async function createOperator(event) {
  event.preventDefault();
  try {
    const payload = await operatorCommand("/v1/control-plane/operators", {
      username: byId("operator-username").value.trim(),
      display_name: byId("operator-display-name").value.trim(),
      role: byId("operator-role").value,
    });
    text("operator-token-output", `Credential for ${payload.username}: ${payload.token}`);
    event.target.reset();
    await refresh();
  } catch (error) { text("operator-token-output", `Operator creation failed: ${error.message}`); }
}

async function updateOperator(operatorItem) {
  const displayName = window.prompt("Operator display name", operatorItem.display_name);
  if (displayName === null) return;
  const role = window.prompt("Role: viewer, operator, or maintainer", operatorItem.role);
  if (role === null) return;
  const normalizedRole = role.trim().toLowerCase();
  if (!["viewer", "operator", "maintainer"].includes(normalizedRole)) {
    text("operator-token-output", "Operator update failed: invalid role");
    return;
  }
  try {
    await operatorCommand(`/v1/control-plane/operators/${operatorItem.operator_id}/update`, {
      expected_revision: operatorItem.revision,
      display_name: displayName.trim(),
      role: normalizedRole,
      additional_permissions: operatorItem.additional_permissions,
    });
    text("operator-token-output", `${operatorItem.username}: profile updated`);
    await refresh();
  } catch (error) { text("operator-token-output", `Operator update failed: ${error.message}`); }
}

async function operatorLifecycle(operatorItem, action) {
  if (action === "revoke" && !window.confirm(`Permanently revoke ${operatorItem.username}?`)) return;
  try {
    await operatorCommand(`/v1/control-plane/operators/${operatorItem.operator_id}/${action}`, { expected_revision: operatorItem.revision });
    text("operator-token-output", `${operatorItem.username}: ${action} completed`);
    await refresh();
  } catch (error) { text("operator-token-output", `Operator action failed: ${error.message}`); }
}

async function rotateOperator(operatorItem) {
  if (!window.confirm(`Rotate the credential for ${operatorItem.username}? Existing sessions will be revoked.`)) return;
  try {
    const payload = await operatorCommand(`/v1/control-plane/operators/${operatorItem.operator_id}/rotate`, { expected_revision: operatorItem.revision });
    text("operator-token-output", `New credential for ${payload.username}: ${payload.token}`);
    await refresh();
  } catch (error) { text("operator-token-output", `Credential rotation failed: ${error.message}`); }
}

async function connect(token, alreadySession = false) {
  state.token = token.trim();
  text("login-error", "");
  try {
    if (!alreadySession) {
      const exchange = await exchangeOperatorCredential(state.token);
      if (exchange) {
        state.token = exchange.session_token;
        state.operatorMode = true;
        state.temporarySession = true;
        state.me = { username: exchange.username, permissions: [] };
      } else {
        state.operatorMode = false;
        state.temporarySession = false;
        state.me = null;
      }
    }
    sessionStorage.setItem("phoenix.controlPlane.token", state.token);
    sessionStorage.setItem("phoenix.controlPlane.operatorMode", state.operatorMode ? "1" : "0");
    sessionStorage.setItem("phoenix.controlPlane.temporarySession", state.temporarySession ? "1" : "0");
    await api("/v1/control-plane/health");
    if (state.operatorMode) state.me = await api("/v1/control-plane/operator/me");
    await issueCsrf();
  } catch (error) {
    sessionStorage.removeItem("phoenix.controlPlane.token"); sessionStorage.removeItem("phoenix.controlPlane.csrf");
    sessionStorage.removeItem("phoenix.controlPlane.operatorMode"); sessionStorage.removeItem("phoenix.controlPlane.temporarySession");
    state.token = ""; state.csrf = ""; state.me = null; state.operatorMode = false; state.temporarySession = false;
    text("login-error", error.message === "unauthorized" ? "The operator credential was rejected." : "The local API is unavailable.");
    return;
  }
  setConnected(true, "Connected");
  await refresh();
  state.refreshTimer = window.setInterval(refresh, 5000);
  state.eventLoop = eventLoop();
}

async function disconnect(reason = "Disconnected") {
  state.connected = false;
  if (state.refreshTimer) window.clearInterval(state.refreshTimer);
  if (state.operatorMode && state.token) {
    try { await request("/v1/control-plane/operator/logout", { method: "POST" }); } catch (_) { /* local cleanup still wins */ }
  }
  state.refreshTimer = null; state.cursor = 0; state.token = ""; state.csrf = ""; state.operations = {}; state.me = null; state.operatorMode = false; state.temporarySession = false;
  sessionStorage.removeItem("phoenix.controlPlane.token");
  sessionStorage.removeItem("phoenix.controlPlane.csrf");
  sessionStorage.removeItem("phoenix.controlPlane.operatorMode");
  sessionStorage.removeItem("phoenix.controlPlane.temporarySession");
  byId("token").value = "";
  text("operator-identity", "Anonymous");
  setConnected(false, reason);
}


byId("login-form").addEventListener("submit", (event) => { event.preventDefault(); connect(byId("token").value); });
byId("create-job-form").addEventListener("submit", createJob);
byId("create-operator-form").addEventListener("submit", createOperator);
byId("history-operator").addEventListener("change", refresh);
byId("refresh").addEventListener("click", refresh);
byId("disconnect").addEventListener("click", () => disconnect());
window.addEventListener("pagehide", () => { state.connected = false; });

if (state.token) connect(state.token, state.temporarySession);
else setConnected(false, "Disconnected");
