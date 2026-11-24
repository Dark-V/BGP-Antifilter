import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { test } from "node:test";

globalThis.localStorage = {getItem: () => "en"};
const modulesUrl = new URL("../../admin-ui/modules/", import.meta.url);
const { api } = await import(new URL("api.js", modulesUrl));
const { locale, t } = await import(new URL("i18n.js", modulesUrl));
const { escapeHtml } = await import(new URL("dom.js", modulesUrl));
const { formatCountdown, formatDurationSeconds } = await import(new URL("format.js", modulesUrl));
const { dnsProxyState, loadDnsProxyStatus, renderDnsProxyStatus } = await import(new URL("dns-proxy.js", modulesUrl));
const { buildStages, rowLevel } = await import(new URL("dashboard.js", modulesUrl));
const { eventLevel, renderSourceWarnings, renderSourceDetails } = await import(new URL("results.js", modulesUrl));
const { runtimeGenerationState } = await import(new URL("runtime.js", modulesUrl));
const { ipv4Range, matchingRoutes, groupLogLines, logSeverity, renderCheckIpResult, renderCheckTargetResult } = await import(new URL("tools.js", modulesUrl));
const { settingsFormValues, applySettingsFormValues } = await import(new URL("settings.js", modulesUrl));
const { parseListLines, parseNamedUrlSourceLine, serializeNamedUrlSource } = await import(new URL("lists.js", modulesUrl));
const { operationState, renderStoredReloadResult } = await import(new URL("operations.js", modulesUrl));
const { applyUpdate, loadUpdateStatus, renderUpdateStatus, updateState, releaseExcerpt } = await import(new URL("updates.js", modulesUrl));

test("all feature modules resolve and their import graph has no cycles", async () => {
  const graph = new Map();
  for (const name of await readdir(modulesUrl)) {
    if (!name.endsWith(".js")) continue;
    const url = new URL(name, modulesUrl);
    const source = await readFile(url, "utf8");
    const imports = [...source.matchAll(/from\s+"(\.\.?\/[^"\n]+)"/g)].map(match => new URL(match[1], url).href);
    graph.set(url.href, imports);
    await import(url);
  }
  function visit(url, ancestors = []) {
    assert.ok(!ancestors.includes(url), `Circular import: ${[...ancestors, url].join(" -> ")}`);
    assert.ok(graph.has(url), `Feature imports outside its module graph: ${url}`);
    for (const dependency of graph.get(url)) visit(dependency, [...ancestors, url]);
  }
  for (const url of graph.keys()) visit(url);
});

test("API requests preserve credentials, JSON bodies and parsed responses", async context => {
  const requests = [];
  context.mock.method(globalThis, "fetch", async (...args) => {
    requests.push(args);
    return new Response(JSON.stringify({accepted: true}), {headers: {"Content-Type": "application/json"}});
  });
  assert.deepEqual(await api("/api/actions/reload", {method: "POST", body: "{}"}), {accepted: true});
  assert.deepEqual(requests, [["/api/actions/reload", {
    credentials: "same-origin", headers: {"Content-Type": "application/json"}, method: "POST", body: "{}",
  }]]);
});

test("API requests preserve text and structured error payloads", async context => {
  context.mock.method(globalThis, "fetch", async () => new Response("route 192.0.2.0/24 blackhole;"));
  assert.equal(await api("/api/routes"), "route 192.0.2.0/24 blackhole;");
  globalThis.fetch = async () => new Response(JSON.stringify({error: "reload already running"}), {
    status: 409, headers: {"Content-Type": "application/json"},
  });
  await assert.rejects(api("/api/actions/reload"), error => error.error === "reload already running");
});

test("translations and duration formatting follow the selected language", () => {
  locale.lang = "en";
  assert.equal(t("unsavedChanges"), "Unsaved changes");
  assert.equal(formatDurationSeconds(3660), "1 h 1 m");
  locale.lang = "ru";
  assert.equal(t("unsavedChanges"), "Есть несохраненные изменения");
  assert.equal(formatDurationSeconds(3660), "1 ч 1 мин");
  assert.equal(t("unknown-key"), "unknown-key");
  locale.lang = "en";
});

test("list parsing retains comments and original row indices for edits", () => {
  const lines = parseListLines("# comment\r\n First | https://example.test/a \r\n\r\nAS64500\n");
  assert.deepEqual(lines.map(line => [line.index, line.value, line.active, line.comment]), [
    [0, "# comment", false, true], [1, "First | https://example.test/a", true, false],
    [2, "", false, false], [3, "AS64500", true, false], [4, "", false, false],
  ]);
});

test("countdown keeps hours separate from minutes and clamps elapsed schedules", context => {
  const now = 1700000000;
  context.mock.method(Date, "now", () => now * 1000);
  for (const [seconds, expected] of [[86400, "24:00:00"], [86376, "23:59:36"], [3600, "01:00:00"], [3599, "59:59"], [65, "01:05"], [0, "00:00"], [-5, "00:00"]]) {
    assert.equal(formatCountdown(now + seconds), expected);
  }
  for (const missing of [undefined, 0, NaN, "invalid"]) assert.equal(formatCountdown(missing), "-");
});

test("domain checks show saved rule matches alongside route membership", () => {
  const html = renderCheckTargetResult({target: "video.example.test", addresses: ["192.0.2.10"],
    domain_rule: {domain: "video.example.test", scope: "saved", action: "include", include_rule: "*.example.test", exclude_rule: null},
    results: [{result: {ip: "192.0.2.10", matched: false, decision: "absent", routes: [], sources: []}}]});
  assert.match(html, /Saved manual rules: matched an include rule/);
  assert.match(html, /Include rule: <code>\*\.example\.test<\/code>/);
  assert.match(html, /Absent from active routes/);
  assert.match(html, /192\.0\.2\.10/);
});

test("DNS failures retain the applied exclusion match without claiming routes were checked", () => {
  const html = renderCheckTargetResult({target: "private.example.test", addresses: [], results: [], lookup_error: "DNS timeout <upstream>",
    domain_rule: {domain: "private.example.test", scope: "active", action: "exclude", include_rule: "example.test", exclude_rule: 'regex:(?<name>private)\\.example\\.test$'}});
  assert.match(html, /Applied rules: matched an exclude rule/);
  assert.match(html, /Include rule.*example\.test/);
  assert.match(html, /Exclude rule.*&lt;name&gt;/);
  assert.match(html, /Could not resolve the domain/);
  assert.match(html, /DNS timeout &lt;upstream&gt;/);
  assert.doesNotMatch(html, /<name>|<upstream>|0\/0 matched|Checked addresses: 0|Absent from active routes/);
});

test("rule evaluation errors are distinct from a domain that matches no rule", () => {
  const response = {target: "video.example.test", addresses: [], results: [], lookup_error: "DNS timeout",
    domain_rule: {domain: "video.example.test", scope: "active", action: "none", error: "Regex timeout <rule>"}};
  const html = renderCheckTargetResult(response);
  assert.match(html, /Applied rules: could not check rules/);
  assert.match(html, /Regex timeout &lt;rule&gt;/);
  assert.doesNotMatch(html, /no matching rules|<rule>/);
  delete response.domain_rule.error;
  assert.match(renderCheckTargetResult(response), /Applied rules: no matching rules/);
});

test("proxy status displays live readiness, IPv6 endpoints and errors, then recovers", async context => {
  const target = {innerHTML: "", textContent: ""};
  const previous = globalThis.document;
  globalThis.document = {getElementById: () => target};
  context.after(() => {globalThis.document = previous; dnsProxyState.status = null; dnsProxyState.error = "";});
  dnsProxyState.status = {enabled: true, running: true, ready: true, bind: "::1", port: 53, upstream: "2001:db8::53", upstream_port: 5353, sync_mode: "bird", routes: 12};
  renderDnsProxyStatus();
  assert.match(target.innerHTML, /Ready/);
  assert.match(target.innerHTML, /\[::1\]:53/);
  assert.match(target.innerHTML, /\[2001:db8::53\]:5353/);
  assert.match(target.innerHTML, /Observed routes.*<strong>12<\/strong>/);
  context.mock.method(globalThis, "fetch", async () => {throw new TypeError("offline <status>");});
  await loadDnsProxyStatus();
  assert.match(target.innerHTML, /offline &lt;status&gt;/);
  globalThis.fetch = async () => new Response(JSON.stringify({enabled: false, configured_enabled: true, requires_restart: true, running: false, ready: false, routes: 0}), {headers: {"Content-Type": "application/json"}});
  await loadDnsProxyStatus();
  assert.match(target.innerHTML, /Disabled/);
  assert.match(target.innerHTML, /Restart the container/);
  assert.doesNotMatch(target.innerHTML, /offline/);
});

test("named URL sources distinguish labels from pipes in URL queries", () => {
  assert.deepEqual(parseNamedUrlSourceLine(" First | https://example.test/list.txt "), {
    name: "First", url: "https://example.test/list.txt", explicitName: true,
  });
  const queryUrl = "https://example.test/list.txt?source=a|b";
  assert.deepEqual(parseNamedUrlSourceLine(queryUrl), {
    name: "example.test · list.txt", url: queryUrl, explicitName: false,
  });
  assert.equal(serializeNamedUrlSource(" First | second ", " https://example.test/list "), "First - second | https://example.test/list");
  assert.equal(parseNamedUrlSourceLine("# ignored"), null);
});

test("runtime stages retain elapsed time, counts and initial startup state", context => {
  context.mock.method(Date, "now", () => 1700000042000);
  assert.equal(runtimeGenerationState({runtime: {generation_active: false}}), null);
  const payload = {runtime: {
    generation_active: true, generation_kind: "initial", generation_started_at_unix: 1700000000,
    generation_items_done: "2", generation_items_total: "5",
  }};
  const state = runtimeGenerationState(payload);
  assert.equal(state.elapsedSeconds, 42);
  assert.equal(state.initial, true);
  assert.equal(state.itemsDone, 2);
  assert.equal(state.itemsTotal, 5);
  const stages = buildStages(payload);
  assert.equal(stages.generator.level, "warn");
  assert.equal(stages.bird.level, "warn");
  assert.equal(stages.peer.level, "warn");
});

test("pipeline stages preserve source failures and BGP establishment", () => {
  const stages = buildStages({status: {success: true, routes: {final: 10}, sources: [
    {status: "fresh"}, {status: "cache", cache_file: "cached"}, {status: "failed"},
  ]}, bird: {ok: true}, bgp: {stdout: "mikrotik BGP master up Established"}});
  assert.equal(stages.sources.level, "fail");
  assert.equal(stages.cache.level, "fail");
  assert.equal(stages.generator.level, "ok");
  assert.equal(stages.bird.level, "ok");
  assert.equal(stages.peer.level, "ok");
});

test("source warnings identify the failed refresh among successful sources and escape its details", () => {
  const sources = Array.from({length: 92}, (_, index) => ({name: `Fresh ${index + 1}`, status: "fresh"}));
  sources.push({name: "Example <mirror>", status: "cache", error: "HTTP 503 <retry>", cache_file: "source.txt"});
  const stage = buildStages({status: {sources}}).sources;
  assert.equal(stage.level, "warn");
  assert.match(stage.subtitle, /93 total · 92 fresh · 1 from cache/);
  const html = renderSourceWarnings(stage.raw);
  assert.match(html, /Update failed; using cached data/);
  assert.match(html, /Example &lt;mirror&gt;/);
  assert.match(html, /HTTP 503 &lt;retry&gt;/);
  assert.doesNotMatch(html, /Fresh 1|<mirror>|<retry>|<details/);
});

test("ordinary cache records and zero counters remain neutral while real skipped domains warn", () => {
  const source = {name: "Example", status: "cache", error: null, cache_file: "source.txt"};
  assert.equal(buildStages({status: {sources: [source]}}).sources.level, "ok");
  assert.equal(eventLevel(source), "ok");
  assert.equal(renderSourceWarnings([source]), "");
  assert.match(renderSourceDetails([source]), /chip ok/);
  assert.doesNotMatch(renderSourceDetails([source]), /chip cache|source-card warn/);
  for (const lang of ["en", "ru"]) {
    locale.lang = lang;
    for (const key of ["fresh", "cachedCount", "cacheHits", "skipped", "skippedSources", "failedCount", "invalid"]) {
      assert.equal(rowLevel(t(key), 0), "", `${lang}: ${key}`);
    }
    assert.equal(rowLevel(t("cachedCount"), 1), "");
    assert.equal(rowLevel(t("failedCount"), 1), "fail");
    assert.equal(rowLevel(t("skipped"), 1), "warn");
  }
  locale.lang = "en";
  for (const problem of [{status: "skipped", error: "DNS timeout"}, {status: "fresh", skipped_domains: 2}, {status: "cache", cached_domains: 3}]) {
    assert.equal(buildStages({status: {sources: [problem]}}).sources.level, "warn");
    assert.notEqual(renderSourceWarnings([problem]), "");
  }
});

test("an old or active reload result cannot replace a pending operation", () => {
  operationState.pendingReloadStartedAtUnix = 200;
  assert.equal(renderStoredReloadResult({reload_result: {started_at_unix: 199, active: false}}), "");
  assert.equal(renderStoredReloadResult({reload_result: {started_at_unix: 201, active: true}}), "");
  const html = renderStoredReloadResult({reload_result: {
    started_at_unix: 201, active: false, ok: true, returncode: 0, stdout: "done <script>", duration_seconds: 1,
  }});
  assert.match(html, /Command completed/);
  assert.match(html, /&lt;script&gt;/);
  operationState.pendingReloadStartedAtUnix = 0;
});

test("rendered text escapes HTML and attribute delimiters", () => {
  assert.equal(escapeHtml('<img src="x"> &'), "&lt;img src=&quot;x&quot;&gt; &amp;");
});

test("IPv4 filtering includes containing and overlapping networks at address boundaries", () => {
  const routes = ["route 0.0.0.0/0 blackhole;", "route 192.0.2.0/24 blackhole;", "route 192.0.2.255/32 blackhole;", "route 198.51.100.0/24 blackhole;"];
  assert.equal(matchingRoutes(routes, "192.0.2.255").length, 3);
  assert.equal(matchingRoutes(routes, "192.0.3.0").length, 1);
  assert.equal(matchingRoutes(routes, "192.0.2.128/25").length, 3);
  assert.deepEqual(ipv4Range("255.255.255.255"), [4294967295, 4294967295]);
  assert.deepEqual(ipv4Range("1.2.3.4/0"), [0, 4294967295]);
  for (const invalid of ["256.0.0.1", "1.2.3", "-1.2.3.4", "1.2.3.4/33", "foo"]) assert.equal(ipv4Range(invalid), null);
});

test("live route checks show DNS origin and BIRD data without claiming a static snapshot", () => {
  const html = renderCheckIpResult({ip: "192.0.2.10", matched: true, decision: "included", live: true,
    confirmed: false, routes: ["192.0.2.10/32"], sources: [],
    dns_origin: {domain: "video.example.test", rule: "regex:(?<video>video)\\.example\\.test$", added_at: 1700000000}});
  assert.match(html, /<h3>Routes in BIRD<\/h3>/);
  assert.match(html, /Included in active routes/);
  assert.match(html, /Route from a DNS reply/);
  assert.match(html, /<strong>video\.example\.test<\/strong>/);
  assert.match(html, /Matching rule: <code>regex:\(\?&lt;video&gt;/);
  assert.match(html, /Added: .*2023/);
  assert.match(html, /Result from the current BIRD routing table/);
  assert.doesNotMatch(html, /Source history is unavailable|Confirmed route snapshot|<h3>Generated routes<\/h3>|<video>/);
  const missingTime = renderCheckIpResult({ip: "192.0.2.10", live: true, matched: true, decision: "included",
    dns_origin: {domain: "video.example.test", rule: "*.example.test", added_at: null}});
  assert.match(missingTime, /Added: unknown time/);
});

test("static route checks keep confirmed snapshot attribution", () => {
  const html = renderCheckIpResult({ip: "192.0.2.10", matched: true, decision: "included", confirmed: true,
    snapshot_applied_at_unix: 1700000000, routes: ["192.0.2.0/24"], sources: []});
  assert.match(html, /<h3>Generated routes<\/h3>/);
  assert.match(html, /Confirmed route snapshot: .*2023/);
  assert.doesNotMatch(html, /current BIRD routing table|Route from a DNS reply/);
});

test("log grouping keeps chronology, first and last timestamps and only merges adjacent repeats", () => {
  const lines = ["bird: 2026-11-15 08:01:01.123 [0001] <ERR> bind failed", "bird: 2026-11-15 08:01:03.999 [0001] <ERR> bind failed", "started", "bird: 2026-11-15 08:01:04.999 [0001] <ERR> bind failed"];
  const groups = groupLogLines(lines);
  assert.equal(groups.length, 3);
  assert.equal(groups[0].count, 2);
  assert.equal(groups[0].first, lines[0]);
  assert.equal(groups[0].last, lines[1]);
  assert.equal(groups[0].level, "error");
  assert.equal(groups[2].count, 1);
});

test("log filters do not treat successful counters or structured info messages as errors", () => {
  assert.equal(logSeverity("Source statuses: fresh=47 cache=0 skipped=0 failed=0"), "info");
  assert.equal(logSeverity('{"level":"info","message":"failed sources: 0"}'), "info");
  assert.equal(logSeverity('{"level":"error","message":"fetch failed"}'), "error");
  assert.equal(logSeverity("fetch failed"), "error");
});

test("release summary shows the latest changelog entry without older releases", () => {
  assert.equal(releaseExcerpt("# Changelog\n\n## 1.2.0\n\n- New feature\n\n## 1.1.0\n- Old feature"), "## 1.2.0\n\n- New feature");
});

test("friendly time inputs round trip seconds without changing API values", context => {
  const inputs = [{dataset: {settingKey: "UPDATE_INTERVAL", multiplier: "60"}, value: "1440"}, {dataset: {settingKey: "CACHE_MAX_AGE", multiplier: "86400"}, value: "7"}, {dataset: {settingKey: "FETCH_TIMEOUT"}, value: "30"}];
  const previous = globalThis.document;
  globalThis.document = {querySelectorAll: () => inputs, querySelector: () => null};
  context.after(() => { globalThis.document = previous; });
  assert.deepEqual(settingsFormValues(), {UPDATE_INTERVAL: "86400", CACHE_MAX_AGE: "604800", FETCH_TIMEOUT: "30"});
  applySettingsFormValues({UPDATE_INTERVAL: "3600", CACHE_MAX_AGE: "172800", FETCH_TIMEOUT: "45"});
  assert.equal(inputs[0].value, 60);
  assert.equal(inputs[1].value, 2);
  assert.equal(settingsFormValues().UPDATE_INTERVAL, "3600");
  for (const [seconds, minutes] of [[30, 0.5], [90, 1.5]]) {
    applySettingsFormValues({UPDATE_INTERVAL: String(seconds)});
    assert.equal(inputs[0].value, minutes);
    assert.equal(settingsFormValues().UPDATE_INTERVAL, String(seconds));
  }
});

test("proxy passwords are omitted until changed and survive form restoration without trimming", context => {
  const password = {type: "password", dataset: {settingKey: "HTTP_PROXY_PASSWORD", hasValue: "1"}, value: ""};
  const username = {type: "text", dataset: {settingKey: "HTTP_PROXY_USERNAME"}, value: " reader "};
  const previous = globalThis.document;
  globalThis.document = {querySelectorAll: () => [username, password], querySelector: () => null};
  context.after(() => { globalThis.document = previous; });
  assert.deepEqual(settingsFormValues(), {HTTP_PROXY_USERNAME: " reader "});
  password.value = ' test <&" password ';
  const typed = settingsFormValues();
  password.value = "";
  applySettingsFormValues(typed);
  assert.equal(password.value, ' test <&" password ');
  assert.deepEqual(settingsFormValues(), typed);
  password.value = "";
  assert.deepEqual(settingsFormValues(), {HTTP_PROXY_USERNAME: " reader "});
  password.dataset.clearSecret = "1";
  const cleared = settingsFormValues();
  assert.deepEqual(cleared, {HTTP_PROXY_USERNAME: " reader ", HTTP_PROXY_PASSWORD: ""});
  password.dataset.clearSecret = "";
  applySettingsFormValues(cleared);
  assert.equal(password.dataset.clearSecret, "1");
  assert.deepEqual(settingsFormValues(), cleared);
});

function installUpdateDom(context) {
  const nodes = new Map();
  function get(id) {
    if (!nodes.has(id)) nodes.set(id, {textContent: "", disabled: false, href: "", className: "",
      classList: {values: new Set(), toggle(name, enabled) { enabled ? this.values.add(name) : this.values.delete(name); }},
      setAttribute(name, value) { this[name] = value; },
      querySelector() { return this.span ||= {textContent: ""}; }});
    return nodes.get(id);
  }
  const previous = globalThis.document;
  globalThis.document = {getElementById: get};
  context.after(() => { globalThis.document = previous; updateState.updateStatusPayload = null; });
  return get;
}

const availableUpdate = {ok: true, current_version: "1.0.0", latest_version: "1.0.1", latest_tag: "v1.0.1",
  update_available: true, apply_available: true, updater_ok: true, runtime: {}};

test("update display covers availability, progress, verification and rollback", context => {
  const get = installUpdateDom(context);
  renderUpdateStatus({...availableUpdate, updater_ok: false, apply_available: false, updater_error: "Portainer"});
  assert.match(get("update-summary").textContent, /Portainer/);
  assert.equal(get("apply-update-btn").disabled, true);
  for (const [stage, label] of [["verifying", "Checking application health"], ["rolling_back", "Restoring previous version"]]) {
    renderUpdateStatus({...availableUpdate, runtime: {active: true, stage, target_version: "1.0.1"}});
    assert.match(get("update-summary").textContent, new RegExp(label));
    assert.equal(get("check-updates-btn").disabled, true);
    assert.equal(get("apply-update-btn").disabled, true);
  }
  for (const ok of [true, false]) {
    renderUpdateStatus({...availableUpdate, runtime: {active: false, success: false, error: "bad image", rollback: {ok}}});
    assert.match(get("update-summary").textContent, /bad image/);
    assert.match(get("update-summary").textContent, ok ? /Rollback completed/ : /Rollback failed/);
  }
});

test("accepted update survives status disconnect and blocks double clicks", async context => {
  const get = installUpdateDom(context);
  renderUpdateStatus(availableUpdate);
  const calls = [];
  let accept;
  context.mock.method(globalThis, "fetch", (url, options) => {
    calls.push([url, options]);
    if (options.method === "POST") return new Promise(resolve => { accept = resolve; });
    throw new TypeError("connection reset during restart");
  });
  const pending = applyUpdate();
  await applyUpdate();
  assert.equal(calls.length, 1);
  assert.equal(get("apply-update-btn").disabled, true);
  accept(new Response(JSON.stringify({accepted: true}), {headers: {"Content-Type": "application/json"}}));
  await pending;
  assert.equal(updateState.updateStatusPayload.runtime.active, true);
  assert.equal(calls[1][0], "/api/update/status");
  assert.deepEqual(JSON.parse(calls[0][1].body), {version: "1.0.1"});
  globalThis.fetch = async () => new Response(JSON.stringify({...availableUpdate, update_available: false,
    apply_available: false, current_version: "1.0.1", runtime: {success: true, active: false, stage: "completed"}}),
    {headers: {"Content-Type": "application/json"}});
  await loadUpdateStatus();
  assert.equal(updateState.updateStatusPayload.runtime.success, true);
  assert.equal(get("update-current-version").textContent, "v1.0.1");
});

test("POST disconnect keeps polling but explicit rejection shows the server error", async context => {
  const get = installUpdateDom(context);
  renderUpdateStatus(availableUpdate);
  context.mock.method(globalThis, "fetch", async () => { throw new TypeError("network error"); });
  await applyUpdate();
  assert.equal(updateState.updateStatusPayload.runtime.active, true);
  assert.match(get("update-summary").textContent, /reconnect/);
  renderUpdateStatus(availableUpdate);
  globalThis.fetch = async () => new Response(JSON.stringify({error: "update already running"}), {
    status: 409, headers: {"Content-Type": "application/json"},
  });
  await applyUpdate();
  assert.equal(updateState.updateStatusPayload.runtime.success, false);
  assert.match(get("update-summary").textContent, /update already running/);
});

test("restart session expiry reloads the login page during an active update", async context => {
  installUpdateDom(context);
  const previous = globalThis.window;
  let reloads = 0;
  globalThis.window = {location: {reload: () => { reloads++; }}};
  context.after(() => { globalThis.window = previous; });
  renderUpdateStatus({...availableUpdate, runtime: {active: true}});
  context.mock.method(globalThis, "fetch", async () => new Response(JSON.stringify({error: "unauthorized"}), {
    status: 401, headers: {"Content-Type": "application/json"},
  }));
  await assert.rejects(loadUpdateStatus());
  assert.equal(reloads, 1);
});
