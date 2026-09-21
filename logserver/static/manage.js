"use strict";

const ui = {
  telegramForm: document.querySelector("#telegramForm"),
  botToken: document.querySelector("#botToken"),
  tokenHint: document.querySelector("#tokenHint"),
  chatId: document.querySelector("#chatId"),
  telegramStatus: document.querySelector("#telegramStatus"),
  testTelegram: document.querySelector("#testTelegram"),
  clearToken: document.querySelector("#clearToken"),
  ruleList: document.querySelector("#ruleList"),
  noRules: document.querySelector("#noRules"),
  newRule: document.querySelector("#newRule"),
  ruleForm: document.querySelector("#ruleForm"),
  ruleId: document.querySelector("#ruleId"),
  ruleEnabled: document.querySelector("#ruleEnabled"),
  ruleName: document.querySelector("#ruleName"),
  ruleQuery: document.querySelector("#ruleQuery"),
  ruleRegex: document.querySelector("#ruleRegex"),
  ipLookupField: document.querySelector("#ipLookupField"),
  batchWindow: document.querySelector("#batchWindow"),
  cooldown: document.querySelector("#cooldown"),
  ruleTemplate: document.querySelector("#ruleTemplate"),
  editorMode: document.querySelector("#editorMode"),
  editorTitle: document.querySelector("#editorTitle"),
  ruleRuntime: document.querySelector("#ruleRuntime"),
  resetRule: document.querySelector("#resetRule"),
  deleteRule: document.querySelector("#deleteRule"),
  placeholderList: document.querySelector("#placeholderList"),
  toast: document.querySelector("#toast"),
};

const state = { rules: [], selectedId: null, toastTimer: null };
const DEFAULT_TEMPLATE = "🚨 {severity} on {source}\n[[body]]\n• {message}";

async function api(path, options = {}) {
  const response = await fetch(path, options);
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error?.message || `Request failed (${response.status})`);
  return body;
}

async function loadAll() {
  try {
    const [settings, rules] = await Promise.all([
      api("/api/admin/telegram"),
      api("/api/admin/rules"),
    ]);
    renderTelegram(settings);
    state.rules = rules.items;
    renderRules();
    if (state.selectedId) {
      const selected = state.rules.find((rule) => rule.id === state.selectedId);
      selected ? editRule(selected) : newRule();
    }
  } catch (error) {
    toast(error.message, true);
  }
}

function renderTelegram(settings) {
  ui.chatId.value = settings.chat_id || "";
  ui.botToken.value = "";
  ui.telegramStatus.textContent = settings.bot_token_configured && settings.chat_id ? "Configured" : "Not configured";
  ui.telegramStatus.classList.toggle("ready", settings.bot_token_configured && Boolean(settings.chat_id));
  ui.tokenHint.textContent = settings.bot_token_configured
    ? "A token is saved. Leave this empty to keep it unchanged."
    : "The token is stored in SQLite and is never returned by the API.";
}

function renderRules() {
  ui.ruleList.replaceChildren(...state.rules.map(ruleCard));
  ui.noRules.hidden = state.rules.length !== 0;
}

function ruleCard(rule) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = `rule-card${rule.id === state.selectedId ? " active" : ""}`;
  const head = document.createElement("div");
  head.className = "rule-card-head";
  const name = document.createElement("strong");
  name.textContent = rule.name;
  const stateLabel = document.createElement("span");
  stateLabel.className = `rule-state${rule.enabled ? "" : " off"}`;
  stateLabel.textContent = rule.enabled ? "Active" : "Paused";
  head.append(name, rule.last_error ? errorDot(rule.last_error) : stateLabel);
  const meta = document.createElement("small");
  meta.textContent = `${rule.sent_count.toLocaleString()} batches sent · ${rule.batch_window_seconds}s batch${rule.ip_lookup_field ? " · IP lookup" : ""}`;
  button.append(head, meta);
  button.addEventListener("click", () => editRule(rule));
  return button;
}

function errorDot(message) {
  const dot = document.createElement("span");
  dot.className = "rule-error-dot";
  dot.title = message;
  return dot;
}

function newRule() {
  state.selectedId = null;
  ui.ruleForm.reset();
  ui.ruleId.value = "";
  ui.ruleEnabled.checked = true;
  ui.batchWindow.value = "2";
  ui.cooldown.value = "0";
  ui.ipLookupField.value = "";
  ui.ruleTemplate.value = DEFAULT_TEMPLATE;
  ui.editorMode.textContent = "New rule";
  ui.editorTitle.textContent = "Create an alert";
  ui.deleteRule.hidden = true;
  ui.ruleRuntime.hidden = true;
  renderRules();
}

function editRule(rule) {
  state.selectedId = rule.id;
  ui.ruleId.value = rule.id;
  ui.ruleEnabled.checked = rule.enabled;
  ui.ruleName.value = rule.name;
  ui.ruleQuery.value = rule.query;
  ui.ruleRegex.value = rule.regex;
  ui.ipLookupField.value = rule.ip_lookup_field || "";
  ui.batchWindow.value = rule.batch_window_seconds;
  ui.cooldown.value = rule.cooldown_seconds;
  ui.ruleTemplate.value = rule.template;
  setRadio("regex_target", rule.regex_target);
  setRadio("parse_mode", rule.parse_mode);
  ui.editorMode.textContent = `Rule #${rule.id}`;
  ui.editorTitle.textContent = rule.name;
  ui.deleteRule.hidden = false;
  if (rule.last_error) {
    ui.ruleRuntime.hidden = false;
    ui.ruleRuntime.className = "runtime-status error";
    ui.ruleRuntime.textContent = `Last delivery error: ${rule.last_error}`;
  } else if (rule.last_sent_at) {
    ui.ruleRuntime.hidden = false;
    ui.ruleRuntime.className = "runtime-status";
    ui.ruleRuntime.textContent = `Last sent ${new Date(rule.last_sent_at).toLocaleString()} · ${rule.sent_count} batches delivered`;
  } else {
    ui.ruleRuntime.hidden = true;
  }
  renderRules();
}

function setRadio(name, value) {
  const input = document.querySelector(`input[name="${name}"][value="${CSS.escape(value)}"]`);
  if (input) input.checked = true;
}

function rulePayload() {
  return {
    name: ui.ruleName.value,
    enabled: ui.ruleEnabled.checked,
    query: ui.ruleQuery.value,
    regex: ui.ruleRegex.value,
    regex_target: document.querySelector('input[name="regex_target"]:checked').value,
    ip_lookup_field: ui.ipLookupField.value,
    template: ui.ruleTemplate.value,
    parse_mode: document.querySelector('input[name="parse_mode"]:checked').value,
    cooldown_seconds: Number(ui.cooldown.value),
    batch_window_seconds: Number(ui.batchWindow.value),
  };
}

ui.telegramForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const payload = { chat_id: ui.chatId.value };
  if (ui.botToken.value) payload.bot_token = ui.botToken.value;
  try {
    renderTelegram(await api("/api/admin/telegram", {
      method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload),
    }));
    toast("Telegram settings saved");
  } catch (error) { toast(error.message, true); }
});

ui.testTelegram.addEventListener("click", async () => {
  ui.testTelegram.disabled = true;
  try {
    await api("/api/admin/telegram/test", { method: "POST" });
    toast("Test message sent");
  } catch (error) { toast(error.message, true); }
  finally { ui.testTelegram.disabled = false; }
});

ui.clearToken.addEventListener("click", async () => {
  if (!confirm("Remove the stored Telegram bot token?")) return;
  try {
    renderTelegram(await api("/api/admin/telegram", {
      method: "PUT", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: ui.chatId.value, clear_token: true }),
    }));
    toast("Bot token removed");
  } catch (error) { toast(error.message, true); }
});

ui.ruleForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const id = ui.ruleId.value;
  try {
    const saved = await api(id ? `/api/admin/rules/${id}` : "/api/admin/rules", {
      method: id ? "PUT" : "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(rulePayload()),
    });
    state.selectedId = saved.id;
    await loadAll();
    toast(id ? "Alert rule updated" : "Alert rule created");
  } catch (error) { toast(error.message, true); }
});

ui.deleteRule.addEventListener("click", async () => {
  const id = ui.ruleId.value;
  if (!id || !confirm("Delete this alert rule?")) return;
  try {
    await api(`/api/admin/rules/${id}`, { method: "DELETE" });
    newRule();
    await loadAll();
    toast("Alert rule deleted");
  } catch (error) { toast(error.message, true); }
});

ui.placeholderList.addEventListener("click", (event) => {
  const value = event.target.dataset.placeholder;
  if (!value) return;
  const start = ui.ruleTemplate.selectionStart;
  ui.ruleTemplate.setRangeText(value, start, ui.ruleTemplate.selectionEnd, "end");
  ui.ruleTemplate.focus();
});

ui.newRule.addEventListener("click", newRule);
ui.resetRule.addEventListener("click", () => state.selectedId
  ? editRule(state.rules.find((rule) => rule.id === state.selectedId))
  : newRule());

function toast(message, isError = false) {
  clearTimeout(state.toastTimer);
  ui.toast.textContent = message;
  ui.toast.className = `toast${isError ? " error" : ""}`;
  ui.toast.hidden = false;
  state.toastTimer = setTimeout(() => { ui.toast.hidden = true; }, 4500);
}

newRule();
loadAll();
