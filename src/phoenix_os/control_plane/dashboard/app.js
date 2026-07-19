"use strict";

const state = {
  token: sessionStorage.getItem("phoenix.controlPlane.token") || "",
  cursor: 0,
  connected: false,
  refreshTimer: null,
  eventLoop: null,
};

const byId = (id) => document.getElementById(id);
const text = (id, value) => { byId(id).textContent = String(value); };
const formatTime = (value) => value ? new Date(value).toLocaleString() : "—";
const statusClass = (value) => `status status-${String(value).replaceAll(" ", "_")}`;

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  headers.set("Authorization", `Bearer ${state.token}`);
  headers.set("Accept", "application/json");
  const response = await fetch(path, { ...options, headers, cache: "no-store" });
  if (response.status === 401 || response.status === 403) throw new Error("unauthorized");
  if (!response.ok) throw new Error(`http_${response.status}`);
  return response.json();
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

function renderJobs(page) {
  const body = byId("jobs-table");
  body.replaceChildren(...page.items.map((job) => {
    const row = document.createElement("tr");
    const capability = document.createElement("td"); capability.textContent = job.capability;
    const status = document.createElement("td");
    const badge = document.createElement("span"); badge.className = statusClass(job.status); badge.textContent = job.status; status.append(badge);
    const attempts = document.createElement("td"); attempts.textContent = `${job.attempts}/${job.max_attempts}`;
    const next = document.createElement("td"); next.textContent = formatTime(job.next_run_at);
    row.append(capability, status, attempts, next); return row;
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
    row.append(name, status, revision, steps); return row;
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

async function refresh() {
  try {
    const [snapshot, jobs, workflows, capabilities, plugins, audit] = await Promise.all([
      api("/v1/control-plane/snapshot"),
      api("/v1/control-plane/jobs?limit=20"),
      api("/v1/control-plane/workflows?limit=20"),
      api("/v1/control-plane/capabilities?limit=50"),
      api("/v1/control-plane/plugins?limit=50"),
      api("/v1/control-plane/audit"),
    ]);
    renderSnapshot(snapshot); renderJobs(jobs); renderWorkflows(workflows);
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

async function connect(token) {
  state.token = token.trim();
  sessionStorage.setItem("phoenix.controlPlane.token", state.token);
  text("login-error", "");
  try {
    await api("/v1/control-plane/health");
  } catch (error) {
    sessionStorage.removeItem("phoenix.controlPlane.token"); state.token = "";
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
  state.refreshTimer = null; state.cursor = 0; state.token = "";
  sessionStorage.removeItem("phoenix.controlPlane.token");
  byId("token").value = "";
  setConnected(false, reason);
}

byId("login-form").addEventListener("submit", (event) => { event.preventDefault(); connect(byId("token").value); });
byId("refresh").addEventListener("click", refresh);
byId("disconnect").addEventListener("click", () => disconnect());
window.addEventListener("pagehide", () => { state.connected = false; });

if (state.token) connect(state.token);
else setConnected(false, "Disconnected");
