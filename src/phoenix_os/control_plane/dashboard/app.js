"use strict";

const state = {
  token: sessionStorage.getItem("phoenix.controlPlane.token") || "",
  csrf: sessionStorage.getItem("phoenix.controlPlane.csrf") || "",
  cursor: 0,
  connected: false,
  refreshTimer: null,
  eventLoop: null,
  operations: {},
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

function renderOperations(payload) {
  state.operations = payload.actions || {};
  const any = Object.values(state.operations).some(Boolean);
  byId("operations-panel").classList.toggle("hidden", !any);
  byId("create-job-submit").disabled = !state.operations["job.create"];
}

async function refresh() {
  try {
    const [snapshot, jobs, workflows, capabilities, plugins, audit, operations] = await Promise.all([
      api("/v1/control-plane/snapshot"),
      api("/v1/control-plane/jobs?limit=20"),
      api("/v1/control-plane/workflows?limit=20"),
      api("/v1/control-plane/capabilities?limit=50"),
      api("/v1/control-plane/plugins?limit=50"),
      api("/v1/control-plane/audit"),
      api("/v1/control-plane/operations"),
    ]);
    renderOperations(operations); renderSnapshot(snapshot); renderJobs(jobs); renderWorkflows(workflows);
    renderStack("capabilities-list", capabilities.items, (item) => [item.name, `${item.risk} risk · ${item.required_permissions.length} permissions`, null]);
    renderStack("plugins-list", plugins.items, (item) => [item.name, `${item.version} · ${item.exports.capabilities} capabilities`, item.status]);
    text("audit-total", audit.available ? audit.records : 0);
    text("audit-summary", audit.available ? `${audit.signed_records} signed · ${audit.verification_failures} verification failures` : "Unavailable");
    setConnected(true, "Connected");
  } catch (error) {
    if (error.message === "unauthorized") disconnect("Token rejected");
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

async function connect(token) {
  state.token = token.trim();
  sessionStorage.setItem("phoenix.controlPlane.token", state.token);
  text("login-error", "");
  try {
    await api("/v1/control-plane/health");
    await issueCsrf();
  } catch (error) {
    sessionStorage.removeItem("phoenix.controlPlane.token"); sessionStorage.removeItem("phoenix.controlPlane.csrf");
    state.token = ""; state.csrf = "";
    text("login-error", error.message === "unauthorized" ? "The administrator token was rejected." : "The local API is unavailable.");
    return;
  }
  setConnected(true, "Connected");
  await refresh();
  state.refreshTimer = window.setInterval(refresh, 5000);
  state.eventLoop = eventLoop();
}

function disconnect(reason = "Disconnected") {
  state.connected = false;
  if (state.refreshTimer) window.clearInterval(state.refreshTimer);
  state.refreshTimer = null; state.cursor = 0; state.token = ""; state.csrf = ""; state.operations = {};
  sessionStorage.removeItem("phoenix.controlPlane.token");
  sessionStorage.removeItem("phoenix.controlPlane.csrf");
  byId("token").value = "";
  setConnected(false, reason);
}

byId("login-form").addEventListener("submit", (event) => { event.preventDefault(); connect(byId("token").value); });
byId("create-job-form").addEventListener("submit", createJob);
byId("refresh").addEventListener("click", refresh);
byId("disconnect").addEventListener("click", () => disconnect());
window.addEventListener("pagehide", () => { state.connected = false; });

if (state.token) connect(state.token);
else setConnected(false, "Disconnected");
