"use strict";

const state = {
  health: null,
  me: null,
  nodes: [],
  services: [],
  trustedHostKeys: "",
  currentView: "overview",
  overviewTimer: null
};

const viewTitles = {
  overview: "Overview",
  nodes: "Nodes",
  services: "Services",
  logs: "Logs",
  updates: "Updates",
  audit: "Audit",
  settings: "Settings"
};

function byId(id) {
  return document.getElementById(id);
}

function clear(element) {
  while (element.firstChild) {
    element.removeChild(element.firstChild);
  }
}

function make(tag, className, text) {
  const element = document.createElement(tag);
  if (className) {
    element.className = className;
  }
  if (text !== undefined && text !== null) {
    element.textContent = String(text);
  }
  return element;
}

function csrfToken() {
  const prefix = "hcc_csrf=";
  for (const raw of document.cookie.split(";")) {
    const value = raw.trim();
    if (value.startsWith(prefix)) {
      return value.slice(prefix.length);
    }
  }
  return "";
}

async function api(path, options) {
  const settings = Object.assign({ method: "GET" }, options || {});
  settings.headers = Object.assign({}, settings.headers || {});
  settings.credentials = "same-origin";

  if (settings.body && typeof settings.body !== "string") {
    settings.headers["Content-Type"] = "application/json";
    settings.body = JSON.stringify(settings.body);
  }
  if (!["GET", "HEAD", "OPTIONS"].includes(settings.method.toUpperCase())) {
    settings.headers["X-CSRF-Token"] = csrfToken();
  }

  const response = await fetch(path, settings);
  let payload = null;
  if (response.status !== 204) {
    try {
      payload = await response.json();
    } catch (error) {
      payload = { error: "The server returned an unreadable response." };
    }
  }
  if (!response.ok) {
    if (response.status === 401 && !path.endsWith("/login") && !path.endsWith("/setup")) {
      await showAuthentication(false);
    }
    throw new Error(payload && payload.error ? payload.error : "Request failed with status " + response.status + ".");
  }
  return payload;
}

function toast(message, isError) {
  const item = make("div", "toast" + (isError ? " error" : ""), message);
  byId("toast-region").appendChild(item);
  window.setTimeout(function () {
    item.remove();
  }, 5000);
}

function setBusy(button, busy, label) {
  if (!button) {
    return;
  }
  if (busy) {
    button.dataset.originalText = button.textContent;
    button.textContent = label || "Working…";
    button.disabled = true;
  } else {
    button.textContent = button.dataset.originalText || button.textContent;
    button.disabled = false;
  }
}

async function start() {
  try {
    const response = await fetch("/api/health", { credentials: "same-origin" });
    state.health = await response.json();
    try {
      state.me = await api("/api/me");
      await showApplication();
    } catch (error) {
      await showAuthentication(Boolean(state.health.setup_required));
    }
  } catch (error) {
    byId("auth-copy").textContent = "The control-center service could not be reached.";
    byId("auth-error").textContent = error.message;
  }
}

async function showAuthentication(setupRequired) {
  state.me = null;
  window.clearInterval(state.overviewTimer);
  byId("app-shell").hidden = true;
  byId("auth-shell").hidden = false;
  byId("auth-error").textContent = "";
  byId("setup-form").hidden = !setupRequired;
  byId("login-form").hidden = setupRequired;
  byId("auth-copy").textContent = setupRequired
    ? "Create the first local administrator using the one-time token printed by the installer."
    : "Sign in with your local control-center account.";
}

async function showApplication() {
  byId("auth-shell").hidden = true;
  byId("app-shell").hidden = false;
  byId("current-user").textContent = state.me.username;
  byId("sidebar-version").textContent = "Version " + state.me.version;
  await loadNodes();
  await activateView("overview");
  window.clearInterval(state.overviewTimer);
  state.overviewTimer = window.setInterval(function () {
    if (state.currentView === "overview") {
      loadOverview(true);
    }
  }, 15000);
}

async function submitSetup(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const button = form.querySelector("button[type=submit]");
  const values = new FormData(form);
  setBusy(button, true, "Creating…");
  byId("auth-error").textContent = "";
  try {
    state.me = await api("/api/setup", {
      method: "POST",
      body: {
        username: values.get("username"),
        password: values.get("password"),
        bootstrap_token: values.get("bootstrap_token")
      }
    });
    form.reset();
    await showApplication();
  } catch (error) {
    byId("auth-error").textContent = error.message;
  } finally {
    setBusy(button, false);
  }
}

async function submitLogin(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const button = form.querySelector("button[type=submit]");
  const values = new FormData(form);
  setBusy(button, true, "Signing in…");
  byId("auth-error").textContent = "";
  try {
    state.me = await api("/api/login", {
      method: "POST",
      body: {
        username: values.get("username"),
        password: values.get("password")
      }
    });
    form.reset();
    await showApplication();
  } catch (error) {
    byId("auth-error").textContent = error.message;
  } finally {
    setBusy(button, false);
  }
}

async function logout() {
  try {
    await api("/api/logout", { method: "POST" });
  } catch (error) {
    toast(error.message, true);
  }
  await showAuthentication(false);
}

async function activateView(viewName) {
  if (!viewTitles[viewName]) {
    return;
  }
  state.currentView = viewName;
  document.querySelectorAll(".view").forEach(function (view) {
    const active = view.id === "view-" + viewName;
    view.hidden = !active;
    view.classList.toggle("active-view", active);
  });
  document.querySelectorAll(".nav-button").forEach(function (button) {
    button.classList.toggle("active", button.dataset.view === viewName);
  });
  byId("page-title").textContent = viewTitles[viewName];

  try {
    if (viewName === "overview") {
      await loadOverview(false);
    } else if (viewName === "nodes") {
      renderNodes();
    } else if (viewName === "services") {
      await loadServices();
    } else if (viewName === "logs") {
      byId("log-output").textContent = "Choose a node and service unit.";
    } else if (viewName === "updates") {
      clear(byId("update-list"));
      byId("update-count").textContent = "Not scanned";
    } else if (viewName === "audit") {
      await loadAudit();
    } else if (viewName === "settings") {
      await loadSettings();
    }
  } catch (error) {
    toast(error.message, true);
  }
}

async function refreshCurrentView() {
  await activateView(state.currentView);
}

function nodeLabel(node) {
  return node.name + (node.id === 0 ? " (local)" : " — " + node.host);
}

function populateNodeSelects() {
  ["services-node", "logs-node", "updates-node"].forEach(function (id) {
    const select = byId(id);
    const selected = select.value;
    clear(select);
    state.nodes.forEach(function (node) {
      const option = make("option", "", nodeLabel(node));
      option.value = String(node.id);
      select.appendChild(option);
    });
    if (Array.from(select.options).some(function (option) { return option.value === selected; })) {
      select.value = selected;
    }
  });
}

async function loadNodes() {
  const payload = await api("/api/nodes");
  state.nodes = payload.nodes;
  populateNodeSelects();
  renderNodes();
}

function renderNodes() {
  const container = byId("node-list");
  clear(container);
  state.nodes.forEach(function (node) {
    const item = make("div", "node-list-item");
    const detail = make("div");
    detail.appendChild(make("strong", "", node.name));
    const target = node.id === 0 ? "Local control host" : node.username + "@" + node.host + ":" + node.port;
    detail.appendChild(make("span", "", target));
    item.appendChild(detail);

    if (node.id === 0) {
      item.appendChild(make("span", "badge online", "Local"));
    } else {
      const remove = make("button", "button ghost", "Remove");
      remove.type = "button";
      remove.addEventListener("click", function () {
        removeNode(node);
      });
      item.appendChild(remove);
    }
    container.appendChild(item);
  });
}

async function probeNode() {
  const form = byId("node-form");
  if (!form.reportValidity()) {
    return;
  }
  const values = new FormData(form);
  const button = byId("probe-node");
  setBusy(button, true, "Probing…");
  byId("fingerprint-box").hidden = true;
  state.trustedHostKeys = "";
  try {
    const payload = await api("/api/nodes/probe", {
      method: "POST",
      body: {
        name: values.get("name"),
        host: values.get("host"),
        port: Number(values.get("port")),
        username: values.get("username")
      }
    });
    state.trustedHostKeys = payload.host_keys;
    byId("fingerprints").textContent = payload.fingerprints.join("\n");
    byId("fingerprint-box").hidden = false;
  } catch (error) {
    toast(error.message, true);
  } finally {
    setBusy(button, false);
  }
}

async function addNode(event) {
  event.preventDefault();
  if (!state.trustedHostKeys) {
    toast("Probe and verify the SSH host key first.", true);
    return;
  }
  const form = event.currentTarget;
  const values = new FormData(form);
  const button = byId("add-node");
  setBusy(button, true, "Adding…");
  try {
    await api("/api/nodes", {
      method: "POST",
      body: {
        name: values.get("name"),
        host: values.get("host"),
        port: Number(values.get("port")),
        username: values.get("username"),
        host_keys: state.trustedHostKeys
      }
    });
    state.trustedHostKeys = "";
    form.reset();
    form.elements.port.value = "22";
    byId("fingerprint-box").hidden = true;
    await loadNodes();
    toast("Node added. It will appear online after its SSH key is authorized.");
  } catch (error) {
    toast(error.message, true);
  } finally {
    setBusy(button, false);
  }
}

async function removeNode(node) {
  if (!window.confirm("Remove " + node.name + " from the dashboard? Its known-host key will be retained.")) {
    return;
  }
  try {
    await api("/api/nodes/" + encodeURIComponent(node.id), { method: "DELETE" });
    await loadNodes();
    toast("Node removed.");
  } catch (error) {
    toast(error.message, true);
  }
}

function bytes(value) {
  const amount = Number(value || 0);
  if (!Number.isFinite(amount) || amount <= 0) {
    return "0 B";
  }
  const units = ["B", "KB", "MB", "GB", "TB", "PB"];
  const power = Math.min(Math.floor(Math.log(amount) / Math.log(1024)), units.length - 1);
  return (amount / Math.pow(1024, power)).toFixed(power > 1 ? 1 : 0) + " " + units[power];
}

function duration(seconds) {
  let value = Math.max(0, Number(seconds || 0));
  const days = Math.floor(value / 86400);
  value %= 86400;
  const hours = Math.floor(value / 3600);
  const minutes = Math.floor((value % 3600) / 60);
  if (days) {
    return days + "d " + hours + "h";
  }
  if (hours) {
    return hours + "h " + minutes + "m";
  }
  return minutes + "m";
}

function average(values) {
  const numbers = values.filter(function (value) {
    return typeof value === "number" && Number.isFinite(value);
  });
  if (!numbers.length) {
    return null;
  }
  return numbers.reduce(function (total, value) { return total + value; }, 0) / numbers.length;
}

function summaryCard(label, value, note) {
  const card = make("article", "panel summary-card");
  card.appendChild(make("span", "", label));
  card.appendChild(make("strong", "", value));
  card.appendChild(make("small", "", note));
  return card;
}

function metric(label, display, percent) {
  const box = make("div", "metric");
  box.appendChild(make("span", "", label));
  box.appendChild(make("strong", "", display));
  const progress = make("progress");
  progress.max = 100;
  progress.value = Math.max(0, Math.min(100, Number(percent || 0)));
  progress.setAttribute("aria-label", label + " " + display);
  box.appendChild(progress);
  return box;
}

function renderOverview(nodes) {
  const online = nodes.filter(function (node) { return node.online; });
  const offline = nodes.length - online.length;
  const cpuAverage = average(online.map(function (node) { return node.cpu_percent; }));
  const memoryAverage = average(online.map(function (node) {
    return node.memory ? node.memory.percent : null;
  }));
  const updateTotal = online.reduce(function (total, node) {
    return total + (typeof node.updates === "number" ? node.updates : 0);
  }, 0);

  const summary = byId("fleet-summary");
  clear(summary);
  summary.appendChild(summaryCard("Online nodes", online.length + " / " + nodes.length, offline ? offline + " need attention" : "All reachable"));
  summary.appendChild(summaryCard("Average CPU", cpuAverage === null ? "Sampling" : cpuAverage.toFixed(1) + "%", "Across online nodes"));
  summary.appendChild(summaryCard("Average memory", memoryAverage === null ? "—" : memoryAverage.toFixed(1) + "%", "Across online nodes"));
  summary.appendChild(summaryCard("Known updates", String(updateTotal), "Local cached count"));

  const container = byId("node-cards");
  clear(container);
  nodes.forEach(function (node) {
    const card = make("article", "panel node-card" + (node.online ? "" : " offline"));
    const head = make("div", "node-card-head");
    const title = make("div");
    title.appendChild(make("h4", "", node.name));
    title.appendChild(make("p", "", node.host + (node.os ? " · " + node.os : "")));
    head.appendChild(title);
    head.appendChild(make("span", "badge " + (node.online ? "online" : "offline"), node.online ? "Online" : "Offline"));
    card.appendChild(head);

    if (!node.online) {
      card.appendChild(make("p", "muted compact", node.error || "Node is unavailable."));
      container.appendChild(card);
      return;
    }

    const metrics = make("div", "metric-grid");
    metrics.appendChild(metric("CPU", node.cpu_percent === null ? "Sampling" : node.cpu_percent + "%", node.cpu_percent || 0));
    metrics.appendChild(metric("Memory", node.memory.percent + "%", node.memory.percent));
    metrics.appendChild(metric("Disk", node.disk.percent + "%", node.disk.percent));
    metrics.appendChild(metric("Load 1m", String(node.load[0]), Math.min(100, Number(node.load[0]) * 10)));
    card.appendChild(metrics);

    const meta = make("div", "node-meta");
    meta.appendChild(make("span", "", "Uptime " + duration(node.uptime_seconds)));
    meta.appendChild(make("span", "", "RAM " + bytes(node.memory.used) + " / " + bytes(node.memory.total)));
    meta.appendChild(make("span", "", "Net ↓ " + bytes(node.network.received) + " ↑ " + bytes(node.network.sent)));
    card.appendChild(meta);
    container.appendChild(card);
  });
}

async function loadOverview(silent) {
  try {
    const payload = await api("/api/overview");
    renderOverview(payload.nodes);
    byId("last-updated").textContent = "Updated " + new Date(payload.generated_at * 1000).toLocaleTimeString();
  } catch (error) {
    if (!silent) {
      throw error;
    }
  }
}

async function loadServices() {
  const button = byId("load-services");
  setBusy(button, true, "Loading…");
  try {
    const nodeId = Number(byId("services-node").value || 0);
    const payload = await api("/api/services?node_id=" + encodeURIComponent(nodeId));
    state.services = payload.services;
    renderServices();
  } finally {
    setBusy(button, false);
  }
}

function renderServices() {
  const query = byId("service-filter").value.trim().toLowerCase();
  const body = byId("services-body");
  clear(body);
  state.services.filter(function (service) {
    return !query || service.unit.toLowerCase().includes(query) || service.description.toLowerCase().includes(query);
  }).forEach(function (service) {
    const row = make("tr");
    row.appendChild(make("td", "", service.unit));
    const stateCell = make("td");
    stateCell.appendChild(make("span", "badge " + (service.active === "active" ? "active" : "warning"), service.active + " / " + service.sub));
    row.appendChild(stateCell);
    row.appendChild(make("td", "", service.description));
    const actions = make("td");
    ["start", "restart", "stop"].forEach(function (operation) {
      const button = make("button", operation === "stop" ? "button danger" : "button ghost", operation);
      button.type = "button";
      button.addEventListener("click", function () {
        serviceAction(service.unit, operation);
      });
      actions.appendChild(button);
    });
    row.appendChild(actions);
    body.appendChild(row);
  });
}

async function serviceAction(unit, operation) {
  if (operation === "stop" && !window.confirm("Stop " + unit + "?")) {
    return;
  }
  try {
    const nodeId = Number(byId("services-node").value || 0);
    const payload = await api("/api/action/service", {
      method: "POST",
      body: { node_id: nodeId, unit: unit, action: operation }
    });
    byId("service-output").hidden = false;
    byId("service-output").textContent = payload.output || "Action completed.";
    toast(operation + " completed for " + unit + ".");
    await loadServices();
  } catch (error) {
    byId("service-output").hidden = false;
    byId("service-output").textContent = error.message;
    toast(error.message, true);
  }
}

async function loadLogs() {
  const button = byId("load-logs");
  const unit = byId("logs-unit").value.trim();
  const nodeId = Number(byId("logs-node").value || 0);
  const lines = Number(byId("logs-lines").value || 200);
  if (!unit) {
    toast("Enter a .service unit name.", true);
    return;
  }
  setBusy(button, true, "Loading…");
  try {
    const payload = await api(
      "/api/logs?node_id=" + encodeURIComponent(nodeId) +
      "&unit=" + encodeURIComponent(unit) +
      "&lines=" + encodeURIComponent(lines)
    );
    byId("log-output").textContent = payload.lines || "No journal entries were returned.";
  } catch (error) {
    byId("log-output").textContent = error.message;
    toast(error.message, true);
  } finally {
    setBusy(button, false);
  }
}

async function scanUpdates() {
  const button = byId("scan-updates");
  setBusy(button, true, "Scanning…");
  try {
    const nodeId = Number(byId("updates-node").value || 0);
    const payload = await api("/api/updates?node_id=" + encodeURIComponent(nodeId));
    const list = byId("update-list");
    clear(list);
    if (!payload.supported) {
      byId("update-count").textContent = "Unsupported";
      list.appendChild(make("p", "muted", payload.message || "This node does not expose apt-get."));
      return;
    }
    byId("update-count").textContent = payload.count + (payload.count === 1 ? " update" : " updates");
    if (!payload.packages.length) {
      list.appendChild(make("p", "muted", "No package updates are currently available."));
    }
    payload.packages.forEach(function (item) {
      const box = make("div", "package-item");
      box.appendChild(make("strong", "", item.name));
      box.appendChild(make("span", "", item.detail));
      list.appendChild(box);
    });
  } finally {
    setBusy(button, false);
  }
}

async function updateAction(operation) {
  const nodeId = Number(byId("updates-node").value || 0);
  const confirmValue = byId("apply-confirm").value;
  const button = operation === "apply" ? byId("apply-updates") : byId("refresh-updates");
  setBusy(button, true, operation === "apply" ? "Applying…" : "Refreshing…");
  try {
    const payload = await api("/api/action/updates", {
      method: "POST",
      body: { node_id: nodeId, operation: operation, confirm: confirmValue }
    });
    byId("update-output").hidden = false;
    byId("update-output").textContent = payload.output || "Action completed.";
    byId("apply-confirm").value = "";
    toast(operation === "apply" ? "Updates applied." : "Package index refreshed.");
    await scanUpdates();
  } catch (error) {
    byId("update-output").hidden = false;
    byId("update-output").textContent = error.message;
    toast(error.message, true);
  } finally {
    setBusy(button, false);
  }
}

async function loadAudit() {
  const payload = await api("/api/audit");
  const body = byId("audit-body");
  clear(body);
  payload.events.forEach(function (event) {
    const row = make("tr");
    row.appendChild(make("td", "", new Date(event.created_at * 1000).toLocaleString()));
    row.appendChild(make("td", "", event.username));
    row.appendChild(make("td", "", event.action));
    row.appendChild(make("td", "", event.target));
    const outcome = make("td");
    outcome.appendChild(make("span", "badge " + (event.outcome === "success" ? "success" : event.outcome === "denied" ? "failed" : "warning"), event.outcome));
    row.appendChild(outcome);
    row.appendChild(make("td", "", event.source_ip));
    body.appendChild(row);
  });
}

async function loadSettings() {
  const payload = await api("/api/settings");
  const values = [
    ["Version", payload.version],
    ["Listener", payload.listener],
    ["Secure cookies", payload.secure_cookies ? "Enabled" : "Disabled"],
    ["Session lifetime", payload.session_hours + " hours"]
  ];
  const list = byId("runtime-settings");
  clear(list);
  values.forEach(function (pair) {
    list.appendChild(make("dt", "", pair[0]));
    list.appendChild(make("dd", "", pair[1]));
  });
  byId("ssh-public-key").textContent = payload.ssh_public_key || "SSH public key is unavailable. Run sudo homelabctl doctor.";
}

async function copyKey() {
  const key = byId("ssh-public-key").textContent;
  try {
    await navigator.clipboard.writeText(key);
    toast("Public key copied.");
  } catch (error) {
    toast("Clipboard access was blocked. Select and copy the key manually.", true);
  }
}

async function changePassword(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const values = new FormData(form);
  const button = form.querySelector("button[type=submit]");
  setBusy(button, true, "Changing…");
  try {
    await api("/api/password", {
      method: "POST",
      body: {
        current_password: values.get("current_password"),
        new_password: values.get("new_password")
      }
    });
    form.reset();
    toast("Password changed. Other sessions were signed out.");
  } catch (error) {
    toast(error.message, true);
  } finally {
    setBusy(button, false);
  }
}

document.addEventListener("DOMContentLoaded", function () {
  byId("setup-form").addEventListener("submit", submitSetup);
  byId("login-form").addEventListener("submit", submitLogin);
  byId("logout-button").addEventListener("click", logout);
  byId("refresh-view").addEventListener("click", refreshCurrentView);
  byId("probe-node").addEventListener("click", probeNode);
  byId("node-form").addEventListener("submit", addNode);
  byId("load-services").addEventListener("click", function () {
    loadServices().catch(function (error) { toast(error.message, true); });
  });
  byId("service-filter").addEventListener("input", renderServices);
  byId("load-logs").addEventListener("click", loadLogs);
  byId("scan-updates").addEventListener("click", function () {
    scanUpdates().catch(function (error) { toast(error.message, true); });
  });
  byId("refresh-updates").addEventListener("click", function () { updateAction("refresh"); });
  byId("apply-updates").addEventListener("click", function () { updateAction("apply"); });
  byId("copy-key").addEventListener("click", copyKey);
  byId("password-form").addEventListener("submit", changePassword);
  document.querySelectorAll(".nav-button").forEach(function (button) {
    button.addEventListener("click", function () {
      activateView(button.dataset.view);
    });
  });
  start();
});
