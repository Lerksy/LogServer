"use strict";

const elements = {
  search: document.querySelector("#search"),
  minimumSeverity: document.querySelector("#minimumSeverity"),
  pageSize: document.querySelector("#pageSize"),
  rows: document.querySelector("#logRows"),
  template: document.querySelector("#rowTemplate"),
  empty: document.querySelector("#emptyState"),
  loadMore: document.querySelector("#loadMore"),
  pause: document.querySelector("#pauseButton"),
  shownCount: document.querySelector("#shownCount"),
  error: document.querySelector("#errorMessage"),
  connection: document.querySelector("#connection"),
  connectionText: document.querySelector("#connectionText"),
  newLogs: document.querySelector("#newLogs"),
  manage: document.querySelector(".manage-link"),
};

const STORAGE_KEY = "logserver.preferences.v1";
const VALID_SEVERITIES = ["emergency", "alert", "critical", "error", "warning", "notice", "info", "debug"];
const VALID_PAGE_SIZES = [50, 100, 250, 500];
const preferences = loadPreferences();
const customSelects = new Set();
let stream = null;

const state = {
  logs: [],
  hasMore: false,
  nextBeforeId: null,
  paused: false,
  pending: 0,
  requestNumber: 0,
  refreshTimer: null,
  expandedLogIds: new Set(),
  expandedMessageIds: new Set(),
};

function endpoint(beforeId = null) {
  const params = new URLSearchParams({
    limit: elements.pageSize.dataset.value,
    minimum_severity: elements.minimumSeverity.dataset.value,
  });
  const query = elements.search.value.trim();
  if (query) params.set("q", query);
  if (beforeId) params.set("before_id", beforeId);
  return `/api/logs?${params}`;
}

function loadPreferences() {
  const defaults = { query: "", minimumSeverity: "debug", pageSize: 100 };
  try {
    const saved = JSON.parse(localStorage.getItem(STORAGE_KEY) || "{}");
    return {
      query: typeof saved.query === "string" ? saved.query : defaults.query,
      minimumSeverity: VALID_SEVERITIES.includes(saved.minimumSeverity)
        ? saved.minimumSeverity
        : defaults.minimumSeverity,
      pageSize: VALID_PAGE_SIZES.includes(Number(saved.pageSize))
        ? Number(saved.pageSize)
        : defaults.pageSize,
    };
  } catch (_error) {
    return defaults;
  }
}

function savePreferences() {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(preferences));
  } catch (_error) {
    // Storage can be unavailable in private or locked-down browser contexts.
  }
}

function setupCustomSelect(root, initialValue, onChange) {
  const trigger = root.querySelector(".select-trigger");
  const current = root.querySelector(".select-current");
  const menu = root.querySelector(".select-menu");
  const options = [...menu.querySelectorAll("[role='option']")];
  customSelects.add(root);

  function close({ restoreFocus = false } = {}) {
    menu.hidden = true;
    root.classList.remove("open");
    trigger.setAttribute("aria-expanded", "false");
    if (restoreFocus) trigger.focus();
  }

  function open() {
    for (const select of customSelects) {
      if (select !== root) select.dispatchEvent(new CustomEvent("close-select"));
    }
    menu.hidden = false;
    root.classList.add("open");
    trigger.setAttribute("aria-expanded", "true");
  }

  function select(value, notify = true) {
    const option = options.find((candidate) => candidate.dataset.value === String(value));
    if (!option) return;
    root.dataset.value = option.dataset.value;
    current.textContent = option.textContent;
    for (const candidate of options) {
      candidate.setAttribute("aria-selected", String(candidate === option));
    }
    close();
    if (notify) onChange(option.dataset.value);
  }

  trigger.addEventListener("click", () => (menu.hidden ? open() : close()));
  trigger.addEventListener("keydown", (event) => {
    if (!["ArrowDown", "ArrowUp", "Home", "End"].includes(event.key)) return;
    event.preventDefault();
    open();
    const selectedIndex = Math.max(0, options.findIndex((option) => option.dataset.value === root.dataset.value));
    const index = event.key === "ArrowUp" || event.key === "End" ? options.length - 1 : selectedIndex;
    options[index].focus();
  });
  menu.addEventListener("keydown", (event) => {
    const index = options.indexOf(document.activeElement);
    if (event.key === "Escape") {
      event.preventDefault();
      close({ restoreFocus: true });
    } else if (["ArrowDown", "ArrowUp", "Home", "End"].includes(event.key)) {
      event.preventDefault();
      let next = event.key === "Home" ? 0 : event.key === "End" ? options.length - 1 : index;
      if (event.key === "ArrowDown") next = (index + 1) % options.length;
      if (event.key === "ArrowUp") next = (index - 1 + options.length) % options.length;
      options[next].focus();
    }
  });
  for (const option of options) {
    option.addEventListener("click", () => select(option.dataset.value));
  }
  root.addEventListener("close-select", () => close());
  select(initialValue, false);
}

async function loadLogs({ append = false } = {}) {
  const requestNumber = ++state.requestNumber;
  hideError();
  try {
    const response = await fetch(endpoint(append ? state.nextBeforeId : null));
    const body = await response.json();
    if (!response.ok) throw new Error(body.error?.message || `Request failed (${response.status})`);
    if (requestNumber !== state.requestNumber) return;
    state.logs = append ? state.logs.concat(body.items) : body.items;
    state.hasMore = body.has_more;
    state.nextBeforeId = body.next_before_id;
    render();
  } catch (error) {
    if (requestNumber === state.requestNumber) showError(error.message);
  }
}

function render() {
  elements.rows.replaceChildren(...state.logs.map(renderRow));
  elements.shownCount.textContent = state.logs.length.toLocaleString();
  elements.empty.hidden = state.logs.length !== 0;
  elements.loadMore.hidden = !state.hasMore;
}

function renderRow(log) {
  const row = elements.template.content.firstElementChild.cloneNode(true);
  const timeElement = row.querySelector(".log-time time");
  const time = formatTime(log.received_at || log.event_at);
  timeElement.dateTime = log.received_at || log.event_at || "";
  timeElement.querySelector(".log-clock").textContent = time.clock;
  timeElement.querySelector(".log-date").textContent = time.date;
  timeElement.title = timestampTitle(log);
  row.querySelector(".source-value").textContent = log.source;

  const severity = row.querySelector(".severity-pill");
  severity.textContent = log.severity;
  severity.dataset.level = log.severity;
  severity.addEventListener("click", () => addFilter(`severity:${quote(log.severity)}`));

  const topics = row.querySelector(".topics-list");
  for (const topic of log.topics) {
    const pill = document.createElement("button");
    pill.type = "button";
    pill.className = "topic-pill";
    pill.textContent = topic;
    pill.addEventListener("click", () => addFilter(`topic:${quote(topic)}`));
    topics.append(pill);
  }
  if (!log.topics.length) topics.textContent = "—";
  renderMessage(row, log);

  if (log.raw || Object.keys(log.metadata || {}).length) {
    const details = row.querySelector(".details");
    details.hidden = false;
    details.open = state.expandedLogIds.has(log.id);
    row.classList.toggle("details-open", details.open);
    details.addEventListener("toggle", () => {
      if (details.open) {
        state.expandedLogIds.add(log.id);
      } else {
        state.expandedLogIds.delete(log.id);
      }
      row.classList.toggle("details-open", details.open);
    });
    details.querySelector("pre").textContent = JSON.stringify(
      { transport: log.transport, facility: log.facility, raw: log.raw, metadata: log.metadata },
      null,
      2,
    );
  }
  return row;
}

function formatTime(value) {
  if (!value) return { clock: "—", date: "Unknown date" };
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) return { clock: value, date: "" };
  return {
    clock: date.toLocaleTimeString(undefined, {
      hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false,
    }),
    date: date.toLocaleDateString(undefined, {
      day: "2-digit", month: "short", year: "numeric",
    }),
  };
}

function timestampTitle(log) {
  const received = readableTimestamp(log.received_at);
  const event = log.event_at ? `\nRouter event: ${readableTimestamp(log.event_at)}` : "";
  return `Received: ${received}${event}`;
}

function readableTimestamp(value) {
  if (!value) return "unknown";
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? value : date.toLocaleString();
}

function renderMessage(row, log) {
  const tag = row.querySelector(".message-tag");
  const value = row.querySelector(".message-value");
  const toggle = row.querySelector(".message-toggle");
  const prefix = log.message.match(/^\[([^\]\r\n]{1,32})\]\s*/);
  if (prefix) {
    tag.hidden = false;
    tag.textContent = `[${prefix[1]}]`;
    value.textContent = log.message.slice(prefix[0].length);
  } else {
    value.textContent = log.message;
  }

  const collapsible = log.message.length > 140 || log.message.includes("\n");
  if (!collapsible) return;
  toggle.hidden = false;
  const applyExpandedState = (expanded) => {
    value.classList.toggle("collapsed", !expanded);
    row.classList.toggle("message-expanded", expanded);
    toggle.textContent = expanded ? "Collapse" : "Expand";
    toggle.setAttribute("aria-expanded", String(expanded));
  };
  applyExpandedState(state.expandedMessageIds.has(log.id));
  toggle.addEventListener("click", () => {
    const expanded = !state.expandedMessageIds.has(log.id);
    if (expanded) state.expandedMessageIds.add(log.id);
    else state.expandedMessageIds.delete(log.id);
    applyExpandedState(expanded);
  });
}

function quote(value) {
  return /\s/.test(value) ? `"${value.replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"` : value;
}

function addFilter(filter) {
  const current = elements.search.value.trim();
  elements.search.value = current ? `${current} AND ${filter}` : filter;
  preferences.query = elements.search.value;
  savePreferences();
  loadLogs();
}

function showError(message) {
  elements.error.textContent = message;
  elements.error.hidden = false;
}

function hideError() {
  elements.error.hidden = true;
}

function scheduleRefresh() {
  clearTimeout(state.refreshTimer);
  state.refreshTimer = setTimeout(() => loadLogs(), 180);
}

elements.search.value = preferences.query;
setupCustomSelect(elements.minimumSeverity, preferences.minimumSeverity, (value) => {
  preferences.minimumSeverity = value;
  savePreferences();
  loadLogs();
});
setupCustomSelect(elements.pageSize, preferences.pageSize, (value) => {
  preferences.pageSize = Number(value);
  savePreferences();
  loadLogs();
});
elements.search.addEventListener("input", () => {
  preferences.query = elements.search.value;
  savePreferences();
  scheduleRefresh();
});
elements.loadMore.addEventListener("click", () => loadLogs({ append: true }));
elements.pause.addEventListener("click", () => {
  state.paused = !state.paused;
  elements.pause.classList.toggle("paused", state.paused);
  elements.pause.querySelector("span:last-child").textContent = state.paused ? "Resume live" : "Pause live";
  elements.pause.querySelector(".pause-symbol").textContent = state.paused ? "▶" : "Ⅱ";
  if (!state.paused && state.pending) {
    state.pending = 0;
    elements.newLogs.hidden = true;
    loadLogs();
  }
});

document.addEventListener("keydown", (event) => {
  if (event.key === "/" && document.activeElement !== elements.search) {
    event.preventDefault();
    elements.search.focus();
  }
  if (event.key === "Escape" && document.activeElement === elements.search) {
    elements.search.value = "";
    preferences.query = "";
    savePreferences();
    elements.search.blur();
    loadLogs();
  }
});
document.addEventListener("pointerdown", (event) => {
  for (const select of customSelects) {
    if (!select.contains(event.target)) select.dispatchEvent(new CustomEvent("close-select"));
  }
});

function closeStream({ inactive = false } = {}) {
  const current = stream;
  stream = null;
  if (current) current.close();
  if (inactive) {
    elements.connection.className = "connection";
    elements.connectionText.textContent = "Inactive";
  }
}

function connectStream() {
  if (document.hidden || stream) return;
  const source = new EventSource("/api/stream");
  stream = source;
  source.onopen = () => {
    if (stream !== source) return;
    elements.connection.className = "connection online";
    elements.connectionText.textContent = "Live";
  };
  source.onerror = () => {
    if (stream !== source) return;
    elements.connection.className = "connection offline";
    elements.connectionText.textContent = "Reconnecting";
  };
  source.addEventListener("log", () => {
    if (stream !== source) return;
    if (state.paused) {
      state.pending += 1;
      elements.newLogs.textContent = `${state.pending.toLocaleString()} new ${state.pending === 1 ? "log" : "logs"}`;
      elements.newLogs.hidden = false;
    } else {
      scheduleRefresh();
    }
  });
}

document.addEventListener("visibilitychange", () => {
  if (document.hidden) {
    closeStream({ inactive: true });
  } else {
    connectStream();
    if (!state.paused) loadLogs();
  }
});
window.addEventListener("pagehide", () => closeStream());
elements.manage.addEventListener("click", () => {
  closeStream({ inactive: true });
  window.setTimeout(() => {
    if (!document.hidden) connectStream();
  }, 1000);
});

connectStream();
loadLogs();
