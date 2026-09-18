"use strict";

const $ = (id) => document.getElementById(id);
const state = {config: null, pooler: "pgbouncer", busy: false, selected: null, events: []};
const titles = {allowed: "Allowed", blocked: "Blocked", error: "Could not verify", unexpected: "Unexpected result"};

function node(tag, text, className) {
  const element = document.createElement(tag);
  if (text !== undefined) element.textContent = String(text);
  if (className) element.className = className;
  return element;
}

async function api(path, options = {}) {
  const response = await fetch(path, {credentials: "same-origin", cache: "no-store", ...options});
  if (!response.ok) throw new Error(`The app returned HTTP ${response.status}. Check the app service logs and try again.`);
  return response.json();
}

function poolerName(id) {
  return state.config.poolers.find((pooler) => pooler.id === id)?.name || id;
}

function actionName(id) {
  return state.config.actions.find((action) => action.id === id)?.label || id;
}

function updatePath() {
  const pooler = state.config.poolers.find((item) => item.id === state.pooler);
  $("path-pooler").textContent = pooler.name;
  $("loopback-port").textContent = `127.0.0.1:${pooler.local_port}`;
  $("path-status").textContent = "Waiting for a query";
  $("path-status").className = "path-status";
  document.querySelectorAll(".action-button").forEach((button) => {
    button.removeAttribute("data-result");
    button.querySelector(".action-arrow").textContent = "›";
  });
}

function setBusy(busy) {
  state.busy = busy;
  document.querySelectorAll(".action-button, #run-all, input[name='pooler']").forEach((element) => {element.disabled = busy;});
  document.querySelector(".evidence-panel").setAttribute("aria-busy", String(busy));
}

function addDetail(label, value) {
  $("connection-details").append(node("dt", label), node("dd", value ?? "Not available"));
}

function renderRows(rows) {
  $("rows-content").replaceChildren();
  if (!rows.length) {
    $("rows-content").append(node("p", "No notes yet. Run “Write a note” to create one."));
    return;
  }
  const table = node("table");
  const head = node("thead");
  const header = node("tr");
  ["ID", "Note", "Created"].forEach((label) => {const th = node("th", label); th.scope = "col"; header.append(th);});
  head.append(header);
  const body = node("tbody");
  rows.forEach((row) => {
    const tr = node("tr");
    tr.append(node("td", row.id), node("td", row.body), node("td", new Date(row.created_at).toLocaleString()));
    body.append(tr);
  });
  table.append(head, body);
  $("rows-content").append(table);
}

function renderEvidence(event) {
  state.selected = event.request_id;
  const evidence = event.evidence;
  const identity = evidence.identity;
  const tls = evidence.tls;
  $("evidence-empty").hidden = true;
  $("evidence-content").hidden = false;
  $("result-action").textContent = actionName(event.action);
  $("result-title").textContent = titles[event.outcome] || event.outcome;
  $("result-title").closest(".result-heading").dataset.outcome = event.outcome;
  $("result-verdict").textContent = event.passed ? "✓ As expected" : "! Needs attention";
  $("result-verdict").className = `verdict ${event.passed ? "pass" : "fail"}`;
  $("result-context").textContent = `${poolerName(event.pooler)} · ${event.duration_ms.toFixed(1)} ms · Expected ${event.expected}`;
  $("current-role").textContent = identity?.current_user ?? "—";
  $("session-role").textContent = identity?.session_user ?? "—";
  $("connection-details").replaceChildren();
  if (identity) {
    addDetail("Database", identity.database);
    addDetail("Backend PID", identity.backend_pid);
    addDetail("Backend address", identity.server_address);
    addDetail("Backend TLS", tls?.ssl ? `${tls.version} · ${tls.cipher}` : "No TLS reported");
    addDetail("Client certificate", tls?.client_dn);
    addDetail("Certificate owner", "Pooler gateway (separate from workload certificate)");
  } else {
    addDetail("Database identity", "No database session was established by this attempt.");
  }
  const failure = evidence.denial || evidence.error;
  $("denial-block").hidden = !failure;
  if (failure) {
    $("denial-title").textContent = evidence.denial ? "Denial evidence" : "Failure evidence";
    $("denial-block").className = `message-block${evidence.error ? " error" : ""}`;
    $("denial-text").textContent = `${failure.sqlstate ? `SQLSTATE ${failure.sqlstate}\n` : ""}${failure.message}${failure.explanation ? `\n\n${failure.explanation}` : ""}`;
  }
  $("control-block").hidden = !evidence.control;
  if (evidence.control) {
    const control = evidence.control;
    $("control-block").className = `control-note${control.available ? "" : " failed"}`;
    $("control-block").textContent = control.available
      ? `✓ Availability control succeeded: ${control.identity.current_user} reached ${control.identity.database} through ${poolerName(event.pooler)} with backend TLS.`
      : `Availability control failed. This result cannot prove a security boundary. ${control.error?.message || "The expected role or gateway certificate was not observed."}`;
  }
  $("probes-block").hidden = !evidence.probes;
  $("probes-block").replaceChildren();
  if (evidence.probes) {
    $("probes-block").append(node("h4", "Direct TCP probes"));
    evidence.probes.forEach((probe) => {
      const row = node("div", undefined, "probe-row");
      row.append(node("strong", probe.target), node("span", probe.status.replaceAll("_", " ")));
      $("probes-block").append(row);
    });
  }
  $("rows-block").hidden = !evidence.rows;
  if (evidence.rows) renderRows(evidence.rows);
  $("sql-block").hidden = !evidence.sql;
  $("sql-text").textContent = evidence.sql || "";
  $("raw-evidence").textContent = JSON.stringify(event, null, 2);
  document.querySelectorAll(".action-button").forEach((button) => {
    button.classList.toggle("active", button.dataset.action === event.action && event.pooler === state.pooler);
  });
  renderFeed();
}

function renderFeed() {
  $("feed-empty").hidden = state.events.length > 0;
  $("attempts-table").hidden = state.events.length === 0;
  $("feed-count").textContent = `${state.events.length} / ${state.config.event_limit}`;
  const rows = state.events.slice().reverse().map((event) => {
    const row = node("tr");
    row.classList.toggle("selected", event.request_id === state.selected);
    const time = node("td", new Date(event.timestamp).toLocaleTimeString([], {hour12: false}));
    const action = node("td");
    const button = node("button", actionName(event.action));
    button.type = "button";
    button.setAttribute("aria-label", `Inspect ${actionName(event.action)}, ${poolerName(event.pooler)}, ${titles[event.outcome]}`);
    button.addEventListener("click", () => renderEvidence(event));
    action.append(button);
    const outcome = node("td");
    outcome.append(node("span", titles[event.outcome] || event.outcome, `feed-outcome ${event.outcome}`));
    row.append(time, action, node("td", poolerName(event.pooler)), outcome, node("td", `${event.duration_ms.toFixed(1)} ms`));
    return row;
  });
  $("attempts-body").replaceChildren(...rows);
}

async function refreshFeed() {
  try {
    const data = await api("/api/events");
    state.events = data.events;
    renderFeed();
  } catch (error) {
    $("feed-count").textContent = "Feed unavailable";
  }
}

async function runOne(action) {
  $("run-status").textContent = `Running: ${actionName(action)}…`;
  const event = await api("/api/run", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({pooler: state.pooler, action})});
  state.events = [...state.events.filter((item) => item.request_id !== event.request_id), event].slice(-state.config.event_limit);
  renderEvidence(event);
  const button = document.querySelector(`[data-action="${action}"]`);
  button.dataset.result = event.outcome;
  button.querySelector(".action-arrow").textContent = event.passed ? "✓" : "!";
  if (event.evidence.identity || event.evidence.control?.available) {
    $("path-status").textContent = event.outcome === "unexpected" ? "Unexpected evidence" : "Path verified by query";
    $("path-status").className = `path-status ${event.outcome === "unexpected" ? "failed" : "verified"}`;
  } else if (event.outcome === "error") {
    $("path-status").textContent = "Connection unverified";
    $("path-status").className = "path-status failed";
  }
  return event;
}

async function runActions(actions) {
  if (state.busy) return;
  setBusy(true);
  let passed = 0;
  try {
    for (const action of actions) {
      const event = await runOne(action);
      if (event.passed) passed += 1;
    }
    $("run-status").textContent = actions.length === 1
      ? `${actionName(actions[0])}: ${passed ? "result matches the expected boundary." : "review the evidence."}`
      : `${passed} of ${actions.length} checks matched expectations through ${poolerName(state.pooler)}.`;
  } catch (error) {
    $("run-status").textContent = error.message;
    $("path-status").textContent = "App connection lost";
    $("path-status").className = "path-status failed";
  } finally {
    setBusy(false);
    await refreshFeed();
  }
}

async function initialize() {
  try {
    state.config = await api("/api/config");
    const config = state.config;
    const number = config.app === "app1" ? "1" : "2";
    const other = number === "1" ? "2" : "1";
    document.body.dataset.app = config.app;
    document.title = `App ${number} · Passwordless pooler lab`;
    $("active-app").textContent = `App ${number}`;
    $("other-app").textContent = `Open App ${other} ↗`;
    const otherUrl = new URL(window.location.href);
    otherUrl.port = String(config.other_app_port);
    otherUrl.pathname = "/";
    otherUrl.search = "";
    otherUrl.hash = "";
    $("other-app").href = otherUrl.href;
    $("app-glyph").textContent = number;
    $("workload-name").textContent = config.app;
    $("workload-schema").textContent = `Own schema: ${config.schema}`;
    $("path-app").textContent = config.app;
    $("workload-cn").textContent = config.workload_certificate;
    config.actions.forEach((action) => {
      const button = node("button", undefined, "action-button");
      button.type = "button";
      button.dataset.action = action.id;
      const copy = node("span", undefined, "action-copy");
      copy.append(node("strong", action.label), node("small", action.description));
      const arrow = node("span", "›", "action-arrow");
      arrow.setAttribute("aria-hidden", "true");
      button.append(copy, arrow);
      button.addEventListener("click", () => runActions([action.id]));
      $(action.expected === "allowed" ? "allowed-actions" : "blocked-actions").append(button);
    });
    document.querySelectorAll("input[name='pooler']").forEach((input) => {
      input.addEventListener("change", () => {
        state.pooler = input.value;
        updatePath();
        $("run-status").textContent = `Ready to check ${poolerName(state.pooler)}.`;
      });
    });
    $("run-all").addEventListener("click", () => runActions(config.actions.map((action) => action.id)));
    await refreshFeed();
    window.setInterval(() => {if (!state.busy && !document.hidden) refreshFeed();}, 4000);
  } catch (error) {
    $("run-status").textContent = error.message;
    $("run-all").disabled = true;
  }
}

initialize();
