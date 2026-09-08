"use strict";

const state = { summary: null, rounds: [], query: "", team: "all", type: "all", status: "all", uptimeWindow: "0" };
const $ = (selector) => document.querySelector(selector);

function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}
function empty(node, message) { clear(node); node.appendChild(element("div", "empty", message)); }
function formatTime(value) { return value ? new Date(value).toLocaleString([], { dateStyle: "medium", timeStyle: "short" }) : "Awaiting data"; }

function setView(name) {
  document.querySelectorAll(".view").forEach((view) => view.classList.toggle("active", view.id === name));
  document.querySelectorAll(".nav-link").forEach((link) => link.classList.toggle("active", link.dataset.view === name));
}

function viewFromLocation() {
  const name = location.hash.replace(/^#view-/, "");
  return ["services", "status-board", "uptime-board", "history"].includes(name) ? name : "status-board";
}

function renderSummary(data) {
  state.summary = data;
  const engine = $("#engine-state");
  engine.className = `engine-state ${data.running ? "online" : "offline"}`;
  engine.lastElementChild.textContent = data.running ? "Engine running" : "Engine idle";
  updateFilters(data.results);
  renderServices();
}

function updateFilters(results) {
  const configure = (selector, values, current) => {
    const select = $(selector);
    const existing = new Set(Array.from(select.options).slice(1).map((option) => option.value));
    values.forEach((value) => {
      if (!existing.has(value)) select.appendChild(new Option(value, value));
    });
    select.value = current;
  };
  configure("#team-filter", [...new Set(results.map((item) => item.team))].sort(), state.team);
  configure("#type-filter", [...new Set(results.map((item) => item.type))].sort(), state.type);
}

function serviceState(item) {
  if (item.passed === null) return "waiting";
  if (item.baseline_state === "mismatch") return "mismatch";
  return item.passed ? "up" : "down";
}

function renderServices() {
  if (!state.summary) return;
  const query = state.query.toLowerCase();
  const results = state.summary.results.filter((item) => {
    const haystack = `${item.id} ${item.name || ""} ${item.team} ${item.host} ${item.type}`.toLowerCase();
    return (!query || haystack.includes(query)) && (state.team === "all" || item.team === state.team) &&
      (state.type === "all" || item.type === state.type) && (state.status === "all" || serviceState(item) === state.status);
  });
  const box = $("#service-rows");
  if (!results.length) return empty(box, "No services match these filters.");
  clear(box);
  results.forEach((item) => {
    const row = element("div", "service-row");
    const name = element("span", "service-name");
    name.appendChild(element("strong", "", item.name || item.id));
    name.appendChild(element("small", "", item.team));
    row.appendChild(name);
    row.appendChild(element("span", "endpoint", `${item.host}:${item.port}`));
    const status = serviceState(item);
    row.appendChild(element("span", `status-badge ${status}`, status));
    row.appendChild(element("span", "latency", item.latency_ms === null || item.latency_ms === undefined ? "—" : `${item.latency_ms} ms`));
    row.appendChild(element("span", "score", item.passed === null ? "—" : `+${item.points || 0}`));
    row.appendChild(element("span", "message", item.message));
    box.appendChild(row);
  });
}

function matrixCellMap(payload) {
  return new Map(payload.cells.map((cell) => [`${cell.team}\u0000${cell.service}`, cell]));
}

function matrixTable(payload, mode) {
  const table = element("table", "matrix-table");
  table.setAttribute("aria-label", mode === "status" ? "Current team service states" : "Historical team service uptime percentages");
  const head = element("thead");
  const headRow = element("tr");
  headRow.appendChild(element("th", "matrix-corner", "Team"));
  payload.services.forEach((service) => {
    const header = element("th", "matrix-service-head");
    header.scope = "col";
    header.title = `${service.label} · ${service.type}`;
    header.appendChild(element("span", "matrix-service-label", service.label));
    headRow.appendChild(header);
  });
  head.appendChild(headRow);
  table.appendChild(head);

  const cells = matrixCellMap(payload);
  const body = element("tbody");
  payload.teams.forEach((team) => {
    const row = element("tr");
    const teamHeader = element("th", "matrix-team", team);
    teamHeader.scope = "row";
    row.appendChild(teamHeader);
    payload.services.forEach((service) => {
      const cell = cells.get(`${team}\u0000${service.key}`);
      const td = element("td", "matrix-cell");
      if (mode === "status") {
        const status = cell ? cell.state : "missing";
        const symbols = { up: "✓", down: "×", waiting: "…", disabled: "—", missing: "—" };
        const labels = { up: "up", down: "down", waiting: "waiting for a result", disabled: "disabled", missing: "not configured" };
        const indicator = element("span", `status-indicator ${status}`, symbols[status] || "—");
        const detail = cell && cell.message ? `: ${cell.message}` : "";
        td.title = `${team} · ${service.label}: ${labels[status]}${detail}`;
        indicator.setAttribute("aria-label", `${service.label} ${labels[status]}`);
        td.appendChild(indicator);
      } else if (!cell || cell.uptime_percent === null || cell.uptime_percent === undefined) {
        td.classList.add("uptime-cell", "uptime-missing");
        td.textContent = "—";
        td.title = `${team} · ${service.label}: no completed checks`;
      } else {
        const percentage = Number(cell.uptime_percent);
        const band = percentage >= 90 ? "uptime-excellent" : percentage >= 75 ? "uptime-good" : percentage >= 50 ? "uptime-warning" : "uptime-critical";
        td.classList.add("uptime-cell", band);
        td.textContent = `${Math.round(percentage)}%`;
        td.title = `${team} · ${service.label}: ${percentage.toFixed(1)}% uptime (${cell.passed_checks}/${cell.checks} checks passed)`;
      }
      row.appendChild(td);
    });
    body.appendChild(row);
  });
  table.appendChild(body);
  return table;
}

function renderStatusMatrix(payload) {
  $("#status-matrix-round").textContent = payload.round || "—";
  $("#status-matrix-updated").textContent = formatTime(payload.last_updated);
  const box = $("#status-matrix");
  if (!payload.teams.length || !payload.services.length) return empty(box, "No configured services are available for the matrix.");
  clear(box);
  box.appendChild(matrixTable(payload, "status"));
}

function renderUptimeMatrix(payload) {
  const box = $("#uptime-matrix");
  const period = $("#uptime-period");
  period.textContent = payload.round_count
    ? `${payload.round_count} round${payload.round_count === 1 ? "" : "s"} · #${payload.first_round}–#${payload.last_round}`
    : "No completed rounds";
  if (!payload.teams.length || !payload.services.length) return empty(box, "No configured services are available for the matrix.");
  clear(box);
  box.appendChild(matrixTable(payload, "uptime"));
}

function renderHistory(rounds) {
  state.rounds = rounds;
  const chart = $("#history-chart");
  const rows = $("#round-rows");
  if (!rounds.length) { empty(chart, "Round history will appear here."); empty(rows, "No completed rounds."); return; }
  clear(chart); clear(rows);
  const highest = Math.max(...rounds.flatMap((round) => round.teams.map((team) => team.points)), 1);
  rounds.forEach((round) => {
    const group = element("div", "round-group");
    const bars = element("div", "bars");
    round.teams.forEach((team) => {
      const bar = element("span", "bar");
      bar.style.height = `${Math.max(2, team.points / highest * 100)}%`;
      bar.title = `${team.team}: ${team.points} points`;
      bars.appendChild(bar);
    });
    group.appendChild(bars); group.appendChild(element("small", "", `R${round.round}`)); chart.appendChild(group);
  });
  rounds.slice().reverse().forEach((round) => {
    const row = element("div", "round-row");
    row.appendChild(element("strong", "", `#${round.round}`));
    const time = element("time", "", formatTime(round.finished_at));
    time.dateTime = round.finished_at;
    row.appendChild(time);
    const chips = element("span", "team-chips");
    round.teams.forEach((team) => {
      const chip = element("span", "team-chip", team.team);
      chip.appendChild(element("b", "", `+${team.points}`));
      chips.appendChild(chip);
    });
    row.appendChild(chips); rows.appendChild(row);
  });
}

async function fetchJSON(url) {
  const response = await fetch(url, { cache: "no-store" });
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
  return response.json();
}

async function refresh() {
  try {
    const [summary, history, statusMatrix, uptimeMatrix] = await Promise.all([
      fetchJSON("/api/v1/summary"),
      fetchJSON("/api/v1/rounds?limit=20"),
      fetchJSON("/api/v1/matrix/status"),
      fetchJSON(`/api/v1/matrix/uptime?rounds=${encodeURIComponent(state.uptimeWindow)}`),
    ]);
    renderSummary(summary); renderHistory(history.rounds); renderStatusMatrix(statusMatrix); renderUptimeMatrix(uptimeMatrix);
    $("#refresh-state").textContent = `Updated ${new Date().toLocaleTimeString()}`;
  } catch (error) {
    const engine = $("#engine-state"); engine.className = "engine-state offline"; engine.lastElementChild.textContent = "Connection lost";
    $("#refresh-state").textContent = "Unable to reach scoring API";
    console.error(error);
  }
}

document.querySelectorAll("[data-view]").forEach((link) => link.addEventListener("click", (event) => {
  event.preventDefault();
  const view = link.dataset.view;
  history.pushState(null, "", `#view-${view}`);
  setView(view);
  requestAnimationFrame(() => window.scrollTo(0, 0));
}));
window.addEventListener("popstate", () => {
  setView(viewFromLocation());
  requestAnimationFrame(() => window.scrollTo(0, 0));
});
$("#service-search").addEventListener("input", (event) => { state.query = event.target.value; renderServices(); });
$("#team-filter").addEventListener("change", (event) => { state.team = event.target.value; renderServices(); });
$("#type-filter").addEventListener("change", (event) => { state.type = event.target.value; renderServices(); });
$("#state-filter").addEventListener("change", (event) => { state.status = event.target.value; renderServices(); });
$("#uptime-window").addEventListener("change", (event) => { state.uptimeWindow = event.target.value; refresh(); });
setView(viewFromLocation());
refresh();
setInterval(() => { if (!document.hidden) refresh(); }, 5000);
