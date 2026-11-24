// Settings form, its saved values and unsaved-change tracking.
import { api } from "./api.js";
import { $, escapeHtml, renderIcons, setStatusTone } from "./dom.js";
import { locale, t } from "./i18n.js";
import { loadDnsProxyStatus, renderDnsProxyStatus } from "./dns-proxy.js";

const settingsState = {
  settingsPayload: null,
  settingsSavedValues: {},
  settingsDirty: false,
};

const settingLabels = {
  UPDATE_INTERVAL: {ru: "Интервал автообновления", en: "Auto refresh interval"},
  CACHE_MAX_AGE: {ru: "Время жизни кеша", en: "Cache lifetime"},
  FETCH_TIMEOUT: {ru: "Таймаут загрузки", en: "Fetch timeout"},
  FETCH_WORKERS: {ru: "Параллельных загрузок", en: "Parallel downloads"},
  FETCH_ATTEMPTS: {ru: "Попыток загрузки", en: "Fetch attempts"},
  FETCH_RETRY_DELAY: {ru: "Пауза между попытками", en: "Retry delay"},
  HTTP_PROXY_TYPE: {ru: "Тип прокси", en: "Proxy type"},
  HTTP_PROXY_HOST: {ru: "IP прокси", en: "Proxy IP"},
  HTTP_PROXY_PORT: {ru: "Порт прокси", en: "Proxy port"},
  HTTP_PROXY_USERNAME: {ru: "Имя пользователя прокси", en: "Proxy username"},
  HTTP_PROXY_PASSWORD: {ru: "Пароль прокси", en: "Proxy password"},
  DNS_RESOLVERS: {ru: "Пользовательские DNS", en: "Custom DNS resolvers"},
  DNS_RESOLVE_TIMEOUT: {ru: "Таймаут DNS-запроса", en: "DNS query timeout"},
  DNS_WORKERS: {ru: "DNS-воркеры", en: "DNS workers"},
  DNS_QPS: {ru: "Лимит DNS-запросов", en: "DNS query limit"},
  DNS_PROXY_ENABLED: {ru: "Включить DNS-прокси", en: "Enable DNS proxy"},
  DNS_PROXY_UPSTREAM: {ru: "DNS-сервер для запросов", en: "Upstream DNS server"},
  DNS_PROXY_UPSTREAM_PORT: {ru: "Порт DNS-сервера", en: "Upstream DNS port"},
  DNS_PROXY_BIND: {ru: "Локальный IP DNS-прокси", en: "DNS proxy local IP"},
  DNS_PROXY_PORT: {ru: "Порт DNS-прокси", en: "DNS proxy port"},
  DNS_PROXY_ALLOWED_CLIENTS: {ru: "Разрешённые клиенты и сети", en: "Allowed clients and networks"},
  DNS_PROXY_HEALTH_PORT: {ru: "Порт проверки готовности", en: "Readiness check port"},
  DNS_HEALTH_DOMAIN: {ru: "Домен для проверки готовности", en: "Readiness check domain"},
  DNS_BGP_PORT: {ru: "Локальный BGP-порт DNS-прокси", en: "DNS proxy local BGP port"},
  DNS_ROUTE_GRACE: {ru: "Запас времени после TTL", en: "Route grace period after TTL"},
  DNS_SYNC_MODE: {ru: "Когда возвращать DNS-ответ", en: "When to return DNS replies"},
  DNS_SYNC_TIMEOUT: {ru: "Таймаут синхронизации маршрутов", en: "Route synchronization timeout"},
  DNS_SYNC_ON_TIMEOUT: {ru: "При ошибке синхронизации", en: "On synchronization failure"},
  INCLUDE_GOOGLE_RANGES: {ru: "Добавлять диапазоны Google", en: "Include Google ranges"},
  REQUIRE_ALL_URL_SOURCES: {ru: "Требовать все URL-источники", en: "Require every URL source"},
  MIN_PREFIX_LENGTH: {ru: "Минимальная длина префикса", en: "Minimum prefix length"},
  ALLOW_BROAD_ROUTES: {ru: "Разрешить широкие маршруты", en: "Allow broad routes"},
  MY_AS: {ru: "AS контейнера", en: "Local AS"},
  PEER_AS: {ru: "AS BGP peer", en: "BGP peer AS"},
  PEER_IP: {ru: "IP BGP peer", en: "BGP peer IP"},
  MT_AS: {ru: "AS BGP peer", en: "BGP peer AS"},
  MT_IP: {ru: "IP BGP peer", en: "BGP peer IP"},
  BIRD_IP: {ru: "IP BIRD", en: "BIRD IP"},
  ROUTER_ID: {ru: "Router ID", en: "Router ID"},
  BGP_COMMUNITY: {ru: "BGP community", en: "BGP community"},
  BGP_PROTOCOL: {ru: "Имя BGP-протокола", en: "BGP protocol name"},
  HEALTHCHECK_REQUIRE_BGP: {ru: "Healthcheck требует BGP", en: "Healthcheck requires BGP"},
};

const settingsSectionLabels = {
  update: "updateSettings",
  sources: "sourceSettings",
  "http-proxy": "httpProxySettings",
  dns: "dnsSettings",
  "dns-proxy": "dnsProxySettings",
  security: "securitySettings",
  bird: "birdSettings",
};

const settingHints = {
  REQUIRE_ALL_URL_SOURCES: "requireAllSourcesHint",
  FETCH_WORKERS: "fetchWorkersHint",
  HTTP_PROXY_TYPE: "httpProxyHint",
  DNS_RESOLVERS: "dnsHint",
  DNS_WORKERS: "dnsWorkersHint",
  DNS_QPS: "dnsQpsHint",
  DNS_PROXY_ENABLED: "dnsProxyEnabledHint",
  DNS_PROXY_UPSTREAM: "dnsProxyUpstreamHint",
  DNS_PROXY_BIND: "dnsProxyBindHint",
  DNS_PROXY_ALLOWED_CLIENTS: "dnsProxyClientsHint",
  DNS_PROXY_HEALTH_PORT: "dnsProxyHealthHint",
  DNS_HEALTH_DOMAIN: "dnsHealthDomainHint",
  DNS_BGP_PORT: "dnsProxyBgpHint",
  DNS_ROUTE_GRACE: "dnsRouteGraceHint",
  DNS_SYNC_MODE: "dnsSyncModeHint",
  DNS_SYNC_TIMEOUT: "dnsSyncTimeoutHint",
  DNS_SYNC_ON_TIMEOUT: "dnsSyncFailureHint",
  ALLOW_BROAD_ROUTES: "broadRoutesHint",
  HEALTHCHECK_REQUIRE_BGP: "healthcheckHint",
};

function settingsPendingLabel(count) {
  return locale.lang === "ru"
    ? `Изменено полей: ${count}`
    : `Changed fields: ${count}`;
}

function settingsFormValues() {
  const values = {};
  document.querySelectorAll("[data-setting-key]").forEach(input => {
    // An untouched blank password keeps the secret already stored by the server.
    if (input.type === "password" && !input.value && input.dataset.clearSecret !== "1") return;
    values[input.dataset.settingKey] = input.type === "checkbox" ? (input.checked ? "1" : "0") : input.dataset.multiplier ? String(Math.round(Number(input.value) * Number(input.dataset.multiplier))) : input.value;
  });
  return values;
}

function applySettingsFormValues(values) {
  document.querySelectorAll("[data-setting-key]").forEach(input => {
    const value = values[input.dataset.settingKey];
    if (value == null) return;
    if (input.type === "checkbox") {
      input.checked = value === "1";
    } else {
      input.value = input.dataset.multiplier ? Number(value) / Number(input.dataset.multiplier) : value;
      if (input.type === "password") input.dataset.clearSecret = value === "" ? "1" : "";
    }
  });
  refreshProxyControls();
}

function refreshProxyControls() {
  const type = document.querySelector('[data-setting-key="HTTP_PROXY_TYPE"]');
  const enabled = type && ["http", "https", "socks5"].includes(type.value);
  for (const key of ["HTTP_PROXY_HOST", "HTTP_PROXY_PORT", "HTTP_PROXY_USERNAME", "HTTP_PROXY_PASSWORD"]) {
    const input = document.querySelector(`[data-setting-key="${key}"]`);
    if (!input) continue;
    input.disabled = !enabled;
    input.required = Boolean(enabled && ["HTTP_PROXY_HOST", "HTTP_PROXY_PORT"].includes(key));
    input.closest(".setting-card").style.display = enabled ? "" : "none";
  }
  refreshPasswordControls();
}

function refreshPasswordControls() {
  const input = document.querySelector('[data-setting-key="HTTP_PROXY_PASSWORD"]');
  if (!input) return;
  const clearing = input.dataset.clearSecret === "1" && !input.value;
  input.placeholder = clearing ? t("proxyPasswordRemovalPending") : input.dataset.hasValue === "1" ? t("proxyPasswordSaved") : "";
  const button = document.querySelector("[data-clear-proxy-password]");
  if (button) button.disabled = input.disabled || clearing;
}

function changedSettingsCount() {
  const values = settingsFormValues();
  return Object.keys(values).filter(key => values[key] !== settingsState.settingsSavedValues[key]).length;
}

function refreshSettingsDirtyState(message = "", tone = "") {
  $("save-settings-btn").disabled = !settingsState.settingsDirty;
  if (message) {
    $("settings-save-status").textContent = message;
    setStatusTone($("settings-save-status"), tone);
    return;
  }
  $("settings-save-status").textContent = settingsState.settingsDirty
    ? settingsPendingLabel(changedSettingsCount())
    : (settingsState.settingsPayload?.settings_file || "");
  setStatusTone($("settings-save-status"), settingsState.settingsDirty ? "warn" : "");
}

function markSettingsDirty() {
  settingsState.settingsDirty = changedSettingsCount() > 0;
  refreshSettingsDirtyState();
}

function settingLabel(key) {
  return settingLabels[key]?.[locale.lang] || settingLabels[key]?.en || key;
}

function settingMultiplier(item) {
  if (item.key === "UPDATE_INTERVAL") return 60;
  const factors = item.key === "CACHE_MAX_AGE" ? [86400] : [];
  const value = Number(item.value);
  return factors.find(factor => value >= factor && value % factor === 0) || 1;
}

function settingOptionLabel(value) {
  if (["http", "https", "socks5"].includes(value)) return value.toUpperCase();
  if (value === "environment") return t("httpProxyEnvironment");
  if (value === "none") return t("httpProxyDisabled");
  return t({async: "dnsSyncAsync", bgp: "dnsSyncBgp", bird: "dnsSyncBird", servfail: "dnsSyncServfail", forward: "dnsSyncForward"}[value] || value);
}

function renderSettingInput(item) {
  const key = escapeHtml(item.key);
  const label = `aria-label="${escapeHtml(settingLabel(item.key))}"`;
  if (item.type === "bool") {
    return `
      <span class="toggle">
        <input type="checkbox" ${label} data-setting-key="${key}" ${item.value === "1" ? "checked" : ""}>
        <span></span>
      </span>`;
  }
  if (item.type === "dns_list") {
    return `<textarea ${label} data-setting-key="${key}" rows="3" spellcheck="false" placeholder="1.1.1.1&#10;8.8.8.8">${escapeHtml(String(item.value || "").replaceAll(",", "\n"))}</textarea>`;
  }
  if (item.type === "cidr_list") {
    return `<textarea ${label} data-setting-key="${key}" rows="3" spellcheck="false">${escapeHtml(String(item.value || "").trim().replace(/[,\s]+/g, "\n"))}</textarea>`;
  }
  if (item.type === "enum") {
    return `<select ${label} data-setting-key="${key}">${(item.options || []).map(value => `<option value="${escapeHtml(value)}" ${value === item.value ? "selected" : ""}>${escapeHtml(settingOptionLabel(value))}</option>`).join("")}</select>`;
  }
  if (item.type === "password") {
    return `<input type="password" ${label} data-setting-key="${key}" data-has-value="${item.has_value ? "1" : "0"}" value="" autocomplete="new-password" spellcheck="false" autocapitalize="off">`;
  }
  const multiplier = settingMultiplier(item);
  const inputType = item.type === "int" || item.type === "number" || item.type === "asn" ? "number" : "text";
  const attrs = [
    `type="${inputType}"`,
    `data-setting-key="${key}"`,
    label,
    item.key === "HTTP_PROXY_USERNAME" ? 'autocomplete="off" spellcheck="false" autocapitalize="off"' : "",
    multiplier > 1 ? `data-multiplier="${multiplier}"` : "",
    `value="${escapeHtml(multiplier > 1 ? Number(item.value) / multiplier : item.value)}"`,
    item.min != null ? `min="${Number(item.min) / multiplier}"` : "",
    item.max != null ? `max="${Number(item.max) / multiplier}"` : "",
    multiplier > 1 ? `step="${1 / multiplier}"` : item.type === "number" ? `step="${escapeHtml(item.step || "any")}"` : "",
  ].filter(Boolean).join(" ");
  return `<input ${attrs}>`;
}

function settingUnit(item) {
  if (!item.unit) return "";
  if (item.unit === "qps") return t("queriesPerSecondUnit");
  if (["sec", "s"].includes(item.unit)) {
    return t({60: "minutesUnit", 86400: "daysUnit"}[settingMultiplier(item)] || "secondsUnit");
  }
  return item.unit;
}

function renderSettingCard(item, sectionItems) {
  if (item.key === "DNS_RESOLVE_TIMEOUT") {
    const hasDnsList = (sectionItems || []).some(candidate => candidate.key === "DNS_RESOLVERS");
    if (hasDnsList) {
      return "";
    }
  }
  const embeddedDnsTimeout = item.key === "DNS_RESOLVERS"
    ? (sectionItems || []).find(candidate => candidate.key === "DNS_RESOLVE_TIMEOUT")
    : null;
  const optional = ["HTTP_PROXY_USERNAME", "HTTP_PROXY_PASSWORD"].includes(item.key);
  const cardTag = item.type === "password" ? "div" : "label";
  return `
    <${cardTag} class="setting-card">
      <span class="setting-head">
        <strong>${escapeHtml(settingLabel(item.key))}${optional ? ` <span class="muted setting-optional">(${t("optional")})</span>` : ""}</strong>
        <span class="setting-badges">
          ${item.requires_restart ? `<span class="chip warn">${t("restartRequired")}</span>` : ""}
        </span>
      </span>
      <span class="setting-control">
        ${renderSettingInput(item)}
        ${item.unit ? `<span class="unit">${escapeHtml(settingUnit(item))}</span>` : ""}
      </span>
      ${item.type === "password" && item.has_value ? `<button type="button" class="setting-secret-clear" data-clear-proxy-password>${t("proxyPasswordClear")}</button>` : ""}
      ${settingHints[item.key] ? `<small class="muted setting-hint">${t(settingHints[item.key])}</small>` : ""}
      ${embeddedDnsTimeout ? `
        <span class="setting-head">
          <strong>${escapeHtml(settingLabel(embeddedDnsTimeout.key))}</strong>
          <span class="setting-badges">
            ${embeddedDnsTimeout.requires_restart ? `<span class="chip warn">${t("restartRequired")}</span>` : ""}
          </span>
        </span>
        <span class="setting-control">
          ${renderSettingInput(embeddedDnsTimeout)}
          ${embeddedDnsTimeout.unit ? `<span class="unit">${escapeHtml(settingUnit(embeddedDnsTimeout))}</span>` : ""}
        </span>
      ` : ""}
    </${cardTag}>
  `;
}

function renderSettings(data) {
  settingsState.settingsPayload = data;
  settingsState.settingsSavedValues = Object.fromEntries((data.sections || []).flatMap(section =>
    (section.items || []).map(item => [item.key, String(item.value)])
  ));
  settingsState.settingsDirty = false;
  $("settings-form").innerHTML = (data.sections || []).map(section => `
    <article class="panel settings-section">
      <h2>${escapeHtml(t(settingsSectionLabels[section.id] || section.title))}</h2>
      ${section.id === "dns-proxy" ? `<div id="dns-proxy-status" class="dns-proxy-status" role="status"></div>` : ""}
      <div class="settings-grid">
        ${(section.items || []).map(item => renderSettingCard(item, section.items || [])).join("")}
      </div>
    </article>
  `).join("");
  settingsState.settingsSavedValues = settingsFormValues();
  refreshProxyControls();
  refreshSettingsDirtyState();
  renderDnsProxyStatus();
}

async function loadSettings() {
  renderSettings(await api("/api/settings"));
  renderIcons();
  await loadDnsProxyStatus();
}

async function saveSettings() {
  if (!$("settings-form").reportValidity()) return false;
  const values = settingsFormValues();
  if (!settingsState.settingsDirty) {
    refreshSettingsDirtyState(t("noChanges"), "ok");
    return true;
  }
  $("save-settings-btn").disabled = true;
  $("settings-save-status").textContent = "...";
  try {
    const result = await api("/api/settings", {
      method: "PUT",
      body: JSON.stringify({values})
    });
    renderSettings(result);
    renderIcons();
    await loadDnsProxyStatus();
    refreshSettingsDirtyState(t("saved"), "ok");
    return true;
  } catch (err) {
    refreshSettingsDirtyState(`${t("failed")}: ${typeof err === "string" ? err : (err.error || err.message || "request failed")}`, "fail");
    return false;
  } finally {
    $("save-settings-btn").disabled = false;
  }
}

function bindSettingsEvents() {
  $("settings-form").addEventListener("submit", event => { event.preventDefault(); saveSettings(); });
  $("save-settings-btn").addEventListener("click", saveSettings);
  $("settings-form").addEventListener("input", event => {
    if (event.target.type === "password" && event.target.value) event.target.dataset.clearSecret = "";
    refreshPasswordControls();
    markSettingsDirty();
  });
  $("settings-form").addEventListener("click", event => {
    if (!event.target.closest("[data-clear-proxy-password]")) return;
    const input = document.querySelector('[data-setting-key="HTTP_PROXY_PASSWORD"]');
    document.querySelector('[data-setting-key="HTTP_PROXY_USERNAME"]').value = "";
    input.value = "";
    input.dataset.clearSecret = "1";
    refreshPasswordControls();
    markSettingsDirty();
  });
  $("settings-form").addEventListener("change", () => {
    refreshProxyControls();
    markSettingsDirty();
  });
}

export {
  applySettingsFormValues,
  bindSettingsEvents,
  loadSettings,
  markSettingsDirty,
  renderSettings,
  saveSettings,
  settingLabel,
  settingsFormValues,
  settingsState
};
