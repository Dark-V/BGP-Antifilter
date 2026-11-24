// DNS proxy readiness, separate from generated-route DNS settings.
import { api } from "./api.js";
import { $, escapeHtml } from "./dom.js";
import { t } from "./i18n.js";

const dnsProxyState = {status: null, error: ""};

function endpoint(address, port) {
  if (!address) return "-";
  const host = String(address).includes(":") ? `[${address}]` : address;
  return `${host}:${port}`;
}

function renderDnsProxyStatus() {
  const target = $("dns-proxy-status");
  if (!target) return;
  if (dnsProxyState.error) {
    target.innerHTML = `<p class="error-inline">${escapeHtml(t("dnsProxyStatusFailed"))}: ${escapeHtml(dnsProxyState.error)}</p>`;
    return;
  }
  const data = dnsProxyState.status;
  if (!data) {
    target.textContent = t("loading");
    return;
  }
  const state = data.running ? (data.ready ? "dnsProxyReady" : "dnsProxyNotReady") : (data.enabled ? "dnsProxyStopped" : "dnsProxyDisabled");
  const tone = data.running && data.ready ? "ok" : data.enabled ? "warn" : "";
  target.innerHTML = `
    <div class="dns-proxy-status-head"><strong>${escapeHtml(t("dnsProxyStatus"))}</strong><span class="chip ${tone}">${escapeHtml(t(state))}</span></div>
    <div class="kv-grid compact">
      <div class="kv"><span>${escapeHtml(t("dnsProxyListen"))}</span><strong>${escapeHtml(endpoint(data.bind, data.port))}</strong></div>
      <div class="kv"><span>${escapeHtml(t("dnsProxyUpstream"))}</span><strong>${escapeHtml(endpoint(data.upstream, data.upstream_port))}</strong></div>
      <div class="kv"><span>${escapeHtml(t("dnsProxyRoutes"))}</span><strong>${escapeHtml(data.routes ?? "-")}</strong></div>
      <div class="kv"><span>${escapeHtml(t("dnsProxyReplyMode"))}</span><strong>${escapeHtml(data.sync_mode || "-")}</strong></div>
    </div>
    ${data.requires_restart ? `<p class="status-warn">${escapeHtml(t("dnsProxyPendingRestart"))}</p>` : ""}
    ${data.last_error ? `<p class="error-inline">${escapeHtml(data.last_error)}</p>` : ""}`;
}

async function loadDnsProxyStatus() {
  if (!$("dns-proxy-status")) return;
  try {
    dnsProxyState.status = await api("/api/dns-proxy/status");
    dnsProxyState.error = "";
  } catch (err) {
    dnsProxyState.error = typeof err === "string" ? err : (err.error || err.message || "request failed");
  }
  renderDnsProxyStatus();
}

export { dnsProxyState, loadDnsProxyStatus, renderDnsProxyStatus };
