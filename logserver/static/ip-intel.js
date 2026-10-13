"use strict";

const ui = {
  addressList: document.querySelector("#addressList"),
  search: document.querySelector("#cacheSearch"),
  rows: document.querySelector("#ipRows"),
  template: document.querySelector("#ipRowTemplate"),
  empty: document.querySelector("#emptyState"),
  loadMore: document.querySelector("#loadMore"),
  error: document.querySelector("#pageError"),
  toast: document.querySelector("#toast"),
  totalCount: document.querySelector("#totalCount"),
  allCount: document.querySelector("#allCount"),
  reportedCount: document.querySelector("#reportedCount"),
  cleanCount: document.querySelector("#cleanCount"),
  unavailableCount: document.querySelector("#unavailableCount"),
  filteredCount: document.querySelector("#filteredCount"),
  manualLookup: document.querySelector("#manualLookup"),
  lookupIp: document.querySelector("#lookupIp"),
  lookupButton: document.querySelector("#lookupButton"),
  lookupStatus: document.querySelector("#lookupStatus"),
  lookupLanguage: document.querySelector("#lookupLanguage"),
};

const STORAGE_KEY = "logserver.ip-intel.address-list.v1";
const state = { items: [], filter: "all", nextOffset: null, request: 0, timer: null };

try {
  ui.addressList.value = localStorage.getItem(STORAGE_KEY) || "logserver-abuse";
} catch (_error) {
  // Browser storage may be unavailable in locked-down contexts.
}

function endpoint(offset = 0) {
  const params = new URLSearchParams({ abuse: state.filter, limit: "100", offset: String(offset) });
  const query = ui.search.value.trim();
  if (query) params.set("q", query);
  return `/api/admin/ip-intel?${params}`;
}

async function loadAddresses({ append = false } = {}) {
  const request = ++state.request;
  ui.error.hidden = true;
  try {
    const response = await fetch(endpoint(append ? state.nextOffset : 0));
    const body = await response.json();
    if (!response.ok) throw new Error(body.error?.message || `Request failed (${response.status})`);
    if (request !== state.request) return;
    state.items = append ? state.items.concat(body.items) : body.items;
    state.nextOffset = body.next_offset;
    render(body);
  } catch (error) {
    if (request !== state.request) return;
    ui.error.textContent = error.message;
    ui.error.hidden = false;
  }
}

function render(body) {
  ui.rows.replaceChildren(...state.items.map(renderRow));
  ui.empty.hidden = state.items.length !== 0;
  ui.loadMore.hidden = !body.has_more;
  ui.totalCount.textContent = body.counts.total.toLocaleString();
  ui.allCount.textContent = body.counts.total.toLocaleString();
  ui.reportedCount.textContent = body.counts.reported.toLocaleString();
  ui.cleanCount.textContent = body.counts.clean.toLocaleString();
  ui.unavailableCount.textContent = body.counts.unavailable.toLocaleString();
  ui.filteredCount.textContent = body.filtered.toLocaleString();
}

function renderRow(item) {
  const row = ui.template.content.firstElementChild.cloneNode(true);
  row.querySelector(".ip-address").textContent = item.ip;
  row.querySelector(".location-primary").textContent = useful(item.country) ? item.country : "Unknown country";
  row.querySelector(".location-city").textContent = useful(item.city) ? item.city : "";
  row.querySelector(".company").textContent = useful(item.company) ? item.company : "Unknown organization";

  const badge = row.querySelector(".abuse-badge");
  badge.classList.add(item.abuse_status);
  badge.textContent = abuseLabel(item);
  row.querySelector(".abuse-summary").textContent = useful(item.abuse_summary) ? item.abuse_summary : "No abuse details";
  row.querySelector(".abuse-date").textContent = item.abuse_last_seen
    ? `Last report ${item.abuse_last_seen}`
    : "";

  const providers = row.querySelector(".provider-list");
  for (const provider of item.providers) {
    const pill = document.createElement("span");
    pill.className = "provider-pill";
    pill.textContent = provider;
    providers.append(pill);
  }
  const cacheDate = row.querySelector(".cache-date");
  cacheDate.textContent = `${item.expired ? "Expired" : "Fetched"} ${formatDate(item.fetched_at)}`;
  cacheDate.title = `Expires ${formatDate(item.expires_at)}`;
  cacheDate.classList.toggle("expired", item.expired);
  const cacheError = row.querySelector(".cache-error");
  cacheError.textContent = item.error || "";

  const copy = row.querySelector(".copy-command");
  copy.addEventListener("click", () => copyRouterCommand(item, copy));
  return row;
}

function abuseLabel(item) {
  if (item.abuse_status === "reported") {
    return `${item.abuse_count} ${item.abuse_count === 1 ? "report" : "reports"}`;
  }
  if (item.abuse_status === "clean") return "No reports";
  return "Unavailable";
}

function useful(value) {
  const normalized = String(value || "").trim().toLowerCase();
  return normalized && normalized !== "unknown" && normalized !== "unavailable";
}

function formatDate(value) {
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? value : date.toLocaleString();
}

function routerOSQuote(value) {
  const safe = String(value).replaceAll("\\", "\\\\").replaceAll('"', '\\"')
    .replaceAll("$", "\\$").replaceAll("\r", " ").replaceAll("\n", " ");
  return `"${safe}"`;
}

function routerCommand(item) {
  const list = ui.addressList.value.trim();
  if (!list) throw new Error("Enter a MikroTik address-list name first");
  const details = item.abuse_status === "reported"
    ? `${item.abuse_count} abuse ${item.abuse_count === 1 ? "report" : "reports"}: ${item.abuse_summary}`
    : `IP intelligence: ${abuseLabel(item)}`;
  const comment = `LogServer — ${details}`.slice(0, 240);
  return `/ip firewall address-list add list=${routerOSQuote(list)} address=${item.ip} comment=${routerOSQuote(comment)}`;
}

async function copyRouterCommand(item, button) {
  try {
    const command = routerCommand(item);
    await copyText(command);
    button.textContent = "Copied";
    button.classList.add("copied");
    showToast(`Command copied for ${item.ip}`);
    window.setTimeout(() => {
      button.textContent = "Copy command";
      button.classList.remove("copied");
    }, 1400);
  } catch (error) {
    ui.addressList.focus();
    showToast(error.message, true);
  }
}

async function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) {
    await navigator.clipboard.writeText(text);
    return;
  }
  const area = document.createElement("textarea");
  area.value = text;
  area.setAttribute("readonly", "");
  area.style.position = "fixed";
  area.style.opacity = "0";
  document.body.append(area);
  area.select();
  const copied = document.execCommand("copy");
  area.remove();
  if (!copied) throw new Error("Could not copy the command in this browser");
}

function showToast(message, error = false) {
  ui.toast.textContent = message;
  ui.toast.className = error ? "toast error" : "toast";
  ui.toast.hidden = false;
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => { ui.toast.hidden = true; }, 2600);
}

function checkedValue(name) {
  return document.querySelector(`input[name="${name}"]:checked`)?.value || "";
}

function updateLookupOptions() {
  ui.lookupLanguage.hidden = checkedValue("lookupProvider") !== "2ip";
}

async function lookupAddress(event) {
  event.preventDefault();
  const ip = ui.lookupIp.value.trim();
  if (!ip) {
    ui.lookupIp.focus();
    return;
  }

  ui.lookupButton.disabled = true;
  ui.lookupButton.textContent = "Looking up…";
  ui.lookupStatus.textContent = "Checking cache and provider";
  ui.lookupStatus.classList.remove("error");
  try {
    const response = await fetch("/api/admin/ip-intel/lookup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ip,
        provider: checkedValue("lookupProvider"),
        language: checkedValue("lookupLanguage") || "en",
      }),
    });
    const body = await response.json();
    if (!response.ok) throw new Error(body.error?.message || `Lookup failed (${response.status})`);

    ui.lookupIp.value = body.item.ip;
    ui.search.value = body.item.ip;
    state.filter = "all";
    document.querySelector('input[name="abuse"][value="all"]').checked = true;
    await loadAddresses();
    const failed = Boolean(body.item.error);
    ui.lookupStatus.textContent = failed ? "Lookup saved with a provider error" : "Lookup complete";
    ui.lookupStatus.classList.toggle("error", failed);
    showToast(
      failed ? `${body.item.ip}: ${body.item.error}` : `IP information loaded for ${body.item.ip}`,
      failed,
    );
  } catch (error) {
    ui.lookupStatus.textContent = error.message;
    ui.lookupStatus.classList.add("error");
    showToast(error.message, true);
  } finally {
    ui.lookupButton.disabled = false;
    ui.lookupButton.textContent = "Get IP info";
  }
}

ui.addressList.addEventListener("input", () => {
  try { localStorage.setItem(STORAGE_KEY, ui.addressList.value); } catch (_error) { /* ignored */ }
});
ui.search.addEventListener("input", () => {
  window.clearTimeout(state.timer);
  state.timer = window.setTimeout(() => loadAddresses(), 180);
});
for (const input of document.querySelectorAll('input[name="abuse"]')) {
  input.addEventListener("change", () => {
    if (!input.checked) return;
    state.filter = input.value;
    loadAddresses();
  });
}
ui.loadMore.addEventListener("click", () => loadAddresses({ append: true }));
ui.manualLookup.addEventListener("submit", lookupAddress);
for (const input of document.querySelectorAll('input[name="lookupProvider"]')) {
  input.addEventListener("change", updateLookupOptions);
}

updateLookupOptions();
loadAddresses();
