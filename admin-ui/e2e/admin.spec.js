import { test, expect } from "@playwright/test";

async function openMenu(page) {
  const toggle = page.locator("#menu-toggle");
  if (await toggle.isVisible() && await toggle.getAttribute("aria-expanded") === "false") await toggle.click();
}
async function navigate(page, view) {
  await openMenu(page);
  await page.locator(`[data-view="${view}"]`).click();
}
async function language(page, lang) {
  await openMenu(page);
  await page.locator(`#lang-${lang}`).click();
  const toggle = page.locator("#menu-toggle");
  if (await toggle.isVisible() && await toggle.getAttribute("aria-expanded") === "true") await toggle.click();
}

test.beforeEach(async ({page, request}) => {
  await request.post("/__test/reset");
  await page.goto("/");
  await page.locator("#password").fill("browser-test");
  await page.locator("#login-form button").click();
  await expect(page.locator("#admin-view")).toBeVisible();
});

test("BGP settings show neutral labels and accept legacy API values", async ({page}) => {
  const response=await page.request.put("/api/settings",{data:{values:{MT_IP:"198.51.100.77",MT_AS:"64577"}}});
  expect(response.ok()).toBeTruthy();
  await page.locator('.flow-node[data-stage="peer"]').click();
  await expect(page.locator("#stage-title")).toHaveText("BGP peer");
  await navigate(page, "settings");
  await expect(page.locator('[data-setting-key="PEER_IP"]')).toHaveValue("198.51.100.77");
  await expect(page.locator('[data-setting-key="PEER_AS"]')).toHaveValue("64577");
  await expect(page.locator('[data-setting-key="MT_IP"]')).toHaveCount(0);
  await page.locator('[data-setting-key="PEER_IP"]').fill("198.51.100.88");
  await page.locator("#save-settings-btn").click();
  await expect(page.locator("#settings-save-status")).toContainText("Saved");
  const values=(await (await page.request.get("/api/settings")).json()).values;
  expect(values.PEER_IP).toBe("198.51.100.88");
  expect(values.PEER_AS).toBe("64577");
  expect(values.MT_IP).toBeUndefined();
  await language(page, "ru");
  await expect(page.getByLabel("IP BGP peer",{exact:true})).toHaveValue("198.51.100.88");
});

test("menu pages and header update button work without a tools or metrics page", async ({page}, testInfo) => {
  const errors = [];
  page.on("pageerror", error => errors.push(error.message));
  await expect(page.locator('[data-view="tools"]')).toHaveCount(0);
  await expect(page.locator('[data-view="updates"]')).toHaveCount(0);
  await expect(page.locator("#service-health")).toHaveCount(0);
  await expect(page.locator("#metrics-view")).toHaveCount(0);
  await expect(page.locator("#open-updates-btn")).toHaveClass(/update-available/);
  expect(await page.locator(".top-actions button").evaluateAll(buttons => buttons.map(button => button.id))).toEqual(["open-updates-btn", "refresh-btn", "logout-btn"]);
  for (const view of ["check", "network", "routes", "logs", "backups", "settings", "dashboard"]) {
    await navigate(page, view);
    await expect(page.locator(`#${view}`)).toBeVisible();
  }
  await page.locator("#open-updates-btn").click();
  await expect(page.locator("#updates")).toBeVisible();
  await expect(page.locator("#update-summary")).toContainText("newer release");
  await expect(page.locator("#open-updates-btn")).toHaveAttribute("aria-label", /Update/);
  await navigate(page, "dashboard");
  await page.screenshot({path: testInfo.outputPath("dashboard.png"), fullPage: true});
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
  expect(errors).toEqual([]);
});

test("route reload and polling never expand the operation log", async ({page}) => {
  const log = page.locator("#operation-log-details");
  await expect(log).not.toHaveAttribute("open", "");
  await page.locator('[data-action="reload"]').click();
  await expect(page.locator("#operation-log")).toContainText("Command completed", {timeout: 10000});
  await expect(log).not.toHaveAttribute("open", "");
  await log.locator(":scope > summary").click();
  await expect(log).toHaveAttribute("open", "");
  await page.locator("#refresh-btn").click();
  await expect(log).toHaveAttribute("open", "");
  await log.locator(":scope > summary").click();
  await page.locator("#refresh-btn").click();
  await expect(log).not.toHaveAttribute("open", "");
});

test("source warnings show the affected source and reason while normal cache and zero counts stay neutral", async ({page}, testInfo) => {
  const status = await (await page.request.get("/api/status")).json();
  let sources = Array.from({length: 92}, (_, index) => ({name: `Fresh ${index + 1}`, status: "fresh"}));
  sources.push({name: "Example mirror", status: "cache", error: "HTTP 503 <upstream>", cache_file: "source.txt"});
  await page.route("**/api/status", route => route.fulfill({json: {...status, status: {...status.status, sources}}}));
  await page.locator("#refresh-btn").click();
  const stage = page.locator('.flow-node[data-stage="sources"]');
  await expect(stage).toHaveClass(/\bwarn\b/);
  await stage.click();
  const warning = page.locator("#stage-details .source-warning-summary");
  await expect(warning).toBeVisible();
  await expect(warning.locator(".kv")).toHaveCount(1);
  await expect(warning).toContainText("Example mirror");
  await expect(warning).toContainText("HTTP 503 <upstream>");
  await expect(warning).toContainText("Update failed; using cached data");
  await expect(page.locator("#stage-details .source-details-collapsed")).not.toHaveAttribute("open", "");
  const zeroRows = await page.locator("#stage-details .kv-grid .kv").evaluateAll(rows => rows.filter(row => row.querySelector("strong").textContent.trim() === "0").map(row => row.className));
  expect(zeroRows).toHaveLength(2);
  for (const className of zeroRows) expect(className).not.toMatch(/warn|fail/);
  await language(page, "ru");
  await expect(warning).toContainText("Не удалось обновить; используются данные из кеша");
  await expect(warning).toContainText("HTTP 503 <upstream>");
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
  await page.locator("#stage-details").screenshot({path: testInfo.outputPath("source-warning.png")});
  sources = [{name: "Example mirror", status: "cache", cache_file: "source.txt"}];
  await page.locator("#refresh-btn").click();
  await expect(stage).toHaveClass(/\bok\b/);
  await expect(warning).toHaveCount(0);
  await expect(page.locator("#stage-details .kv-grid .kv.warn, #stage-details .kv-grid .kv.fail")).toHaveCount(0);
});

test("route search and readable settings preserve seconds when saved", async ({page}) => {
  await navigate(page, "routes");
  await page.locator("#routes-search").fill("192.0.2.10");
  await expect(page.locator("#route-results")).toContainText("192.0.2.0/24");
  await page.locator("#routes-search").fill("300.0.0.1");
  await expect(page.locator("#routes-filter-count")).toContainText("valid IPv4");
  await navigate(page, "settings");
  await expect(page.locator('[data-setting-key="UPDATE_INTERVAL"]')).toHaveValue("30");
  await page.locator('[data-setting-key="UPDATE_INTERVAL"]').fill("45");
  await page.locator('[data-setting-key="CACHE_MAX_AGE"]').fill("2");
  await page.locator("#save-settings-btn").click();
  await expect(page.locator("#settings-save-status")).toContainText("Saved");
  const settings = await (await page.request.get("/api/settings")).json();
  expect(settings.values.UPDATE_INTERVAL).toBe("2700");
  expect(settings.values.CACHE_MAX_AGE).toBe("172800");
  expect((await page.locator('[data-setting-key="DNS_RESOLVERS"]').boundingBox()).height).toBeLessThan(160);
});

test("saved settings retain overrides without changed badges and track unsaved edits globally", async ({page}) => {
  await page.request.put("/api/settings", {data: {values: {FETCH_TIMEOUT: "45", DNS_RESOLVE_TIMEOUT: "4", DNS_PROXY_PORT: "1053"}}});
  await navigate(page, "lists");
  await page.locator('[data-list="google-ranges"]').click();
  await page.locator(".google-ranges-toggle-card").click();
  await expect(page.locator("#list-save-status")).toContainText("Saved");
  await expect.poll(async () => (await (await page.request.get("/api/settings")).json()).values.INCLUDE_GOOGLE_RANGES).toBe("1");
  await navigate(page, "settings");
  await expect(page.locator('[data-setting-key="FETCH_TIMEOUT"]')).toHaveValue("45");
  await expect(page.locator('[data-setting-key="DNS_RESOLVE_TIMEOUT"]')).toHaveValue("4");
  await expect(page.locator('[data-setting-key="DNS_PROXY_PORT"]')).toHaveValue("1053");
  await expect(page.locator("#settings .setting-badges .chip:not(.warn)")).toHaveCount(0);
  const portCard = page.locator(".setting-card").filter({has: page.locator('[data-setting-key="DNS_PROXY_PORT"]')});
  await expect(portCard.locator(".setting-badges .chip.warn")).toHaveText("restart");
  await expect(page.locator("#save-settings-btn")).toBeDisabled();
  await page.locator('[data-setting-key="FETCH_TIMEOUT"]').fill("60");
  await expect(page.locator("#settings-save-status")).toHaveText("Changed fields: 1");
  await expect(page.locator("#save-settings-btn")).toBeEnabled();
  await language(page, "ru");
  await expect(page.locator("#settings-save-status")).toHaveText("Изменено полей: 1");
  await expect(portCard.locator(".setting-badges .chip.warn")).toHaveText("перезапуск");
  await expect(page.locator("#settings .setting-badges .chip:not(.warn)")).toHaveCount(0);
  await page.locator("#save-settings-btn").click();
  await expect(page.locator("#settings-save-status")).toContainText("Сохранено");
  const {values, sections} = await (await page.request.get("/api/settings")).json();
  expect(values.FETCH_TIMEOUT).toBe("60");
  expect(values.DNS_RESOLVE_TIMEOUT).toBe("4");
  expect(values.DNS_PROXY_PORT).toBe("1053");
  expect(values.INCLUDE_GOOGLE_RANGES).toBe("1");
  for (const key of ["FETCH_TIMEOUT", "DNS_RESOLVE_TIMEOUT", "DNS_PROXY_PORT"]) {
    expect(sections.flatMap(section => section.items).find(item => item.key === key).overridden).toBeTruthy();
  }
  await page.reload();
  await navigate(page, "settings");
  await expect(page.locator('[data-setting-key="FETCH_TIMEOUT"]')).toHaveValue("60");
  await expect(page.locator("#save-settings-btn")).toBeDisabled();
  await expect(page.locator("#settings .setting-badges .chip:not(.warn)")).toHaveCount(0);
  await expect(portCard.locator(".setting-badges .chip.warn")).toHaveText("перезапуск");
});

test("DNS and download settings are grouped, bounded and saved", async ({page}) => {
  await navigate(page, "settings");
  await expect(page.locator(".settings-section h2")).toHaveText([
    "Updates and cache", "Source downloads", "HTTP/HTTPS Proxy for requests", "DNS", "DNS proxy", "Route policy", "BIRD / BGP"
  ]);
  const dns = page.locator(".settings-section").filter({has: page.getByRole("heading", {name: "DNS", exact: true})});
  const workers = dns.getByLabel("DNS workers", {exact: true});
  await expect(workers).toHaveValue("16");
  await expect(workers).toHaveAttribute("min", "16");
  await expect(workers).toHaveAttribute("max", "128");
  await expect(dns.getByLabel("DNS query limit", {exact: true})).toHaveValue("50");
  await expect(dns.locator('[data-setting-key="FETCH_WORKERS"]')).toHaveCount(0);
  await expect(page.getByLabel("Parallel downloads", {exact: true})).toHaveValue("8");
  await workers.fill("129");
  expect(await workers.evaluate(input => input.validity.rangeOverflow)).toBeTruthy();
  await workers.fill("64");
  await dns.getByLabel("DNS query limit", {exact: true}).fill("25");
  await page.getByLabel("Parallel downloads", {exact: true}).fill("4");
  await page.locator("#save-settings-btn").click();
  await expect(page.locator("#settings-save-status")).toContainText("Saved");
  const {values} = await (await page.request.get("/api/settings")).json();
  expect([values.DNS_WORKERS, values.DNS_QPS, values.FETCH_WORKERS]).toEqual(["64", "25", "4"]);
  await language(page, "ru");
  await expect(page.locator(".settings-section h2")).toHaveText([
    "Обновление и кеш", "Загрузка источников", "HTTP/HTTPS Прокси для запросов маршрутов", "DNS", "DNS-прокси", "Правила маршрутов", "BIRD / BGP"
  ]);
  await expect(page.getByLabel("DNS-воркеры", {exact: true})).toHaveValue("64");
  await expect(page.getByLabel("Лимит DNS-запросов", {exact: true})).toHaveValue("25");
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
});

test("daily schedules keep minutes in settings and hours in the dashboard countdown", async ({page}) => {
  await page.request.put("/api/settings", {data: {values: {UPDATE_INTERVAL: "90"}}});
  await navigate(page, "settings");
  const interval = page.locator('[data-setting-key="UPDATE_INTERVAL"]');
  await expect(interval).toHaveValue("1.5");
  await expect(interval.locator("..").locator(".unit")).toHaveText("minutes");
  await interval.fill("1440");
  await page.locator("#save-settings-btn").click();
  await expect(page.locator("#settings-save-status")).toContainText("Saved");
  expect((await (await page.request.get("/api/settings")).json()).values.UPDATE_INTERVAL).toBe("86400");
  await page.route("**/api/status", async route => {
    const response = await route.fetch();
    const data = await response.json();
    data.runtime = {...data.runtime, generation_active: false, next_scheduled_update_unix: Math.floor(Date.now() / 1000) + 86376};
    await route.fulfill({response, json: data});
  });
  await navigate(page, "dashboard");
  await page.locator("#refresh-btn").click();
  await expect(page.locator("#next-update")).toHaveText(/23:59:3[0-6]/);
  await navigate(page, "settings");
  await expect(interval).toHaveValue("1440");
  await expect(interval.locator("..").locator(".unit")).toHaveText("minutes");
  await language(page, "ru");
  await expect(interval.locator("..").locator(".unit")).toHaveText("минут");
});

test("DNS proxy settings preserve reply modes, fractional timeouts and client networks", async ({page}, testInfo) => {
  await navigate(page, "settings");
  const stylesheet = page.locator('link[rel="stylesheet"]');
  await expect(stylesheet).toHaveAttribute("href", /^\/styles\.css\?v=[0-9a-f]{16}$/);
  const cssResponse = await page.request.get(await stylesheet.getAttribute("href"));
  expect(cssResponse.ok()).toBeTruthy();
  expect(cssResponse.headers()["cache-control"]).toBe("no-store");
  const proxy = page.locator(".settings-section").filter({has: page.getByRole("heading", {name: "DNS proxy", exact: true})});
  await expect(proxy.getByLabel("Enable DNS proxy", {exact: true})).not.toBeChecked();
  await expect(proxy.getByLabel("Upstream DNS server", {exact: true})).toHaveValue("");
  await expect(proxy.getByLabel("When to return DNS replies", {exact: true})).toHaveValue("async");
  await expect(page.locator("#dns-proxy-status")).toContainText("Disabled");
  await proxy.getByLabel("Upstream DNS server", {exact: true}).fill("2001:db8::53");
  await proxy.getByLabel("Allowed clients and networks", {exact: true}).fill("127.0.0.0/8\n::1/128\n192.0.2.0/24");
  await proxy.getByLabel("When to return DNS replies", {exact: true}).selectOption("bird");
  await proxy.getByLabel("Route synchronization timeout", {exact: true}).fill("0.125");
  await proxy.getByLabel("On synchronization failure", {exact: true}).selectOption("forward");
  await language(page, "ru");
  await expect(page.getByLabel("Когда возвращать DNS-ответ", {exact: true})).toHaveValue("bird");
  await page.locator("#save-settings-btn").click();
  await expect(page.locator("#settings-save-status")).toContainText("Сохранено");
  const {values} = await (await page.request.get("/api/settings")).json();
  expect(values.DNS_PROXY_ENABLED).toBe("0");
  expect(values.DNS_PROXY_UPSTREAM).toBe("2001:db8::53");
  expect(values.DNS_SYNC_MODE).toBe("bird");
  expect(values.DNS_SYNC_TIMEOUT).toBe("0.125");
  expect(values.DNS_SYNC_ON_TIMEOUT).toBe("forward");
  expect(values.DNS_PROXY_ALLOWED_CLIENTS).toContain("192.0.2.0/24");
  const portCard = page.locator('.setting-card').filter({has: page.locator('[data-setting-key="DNS_PROXY_PORT"]')});
  const portGeometry = await portCard.evaluate(card => {
    const head = card.querySelector(".setting-head").getBoundingClientRect();
    const control = card.querySelector(".setting-control").getBoundingClientRect();
    return {controlGap: control.top - head.bottom, bottomGap: card.getBoundingClientRect().bottom - control.bottom};
  });
  expect(portGeometry.controlGap).toBeGreaterThanOrEqual(8);
  expect(portGeometry.controlGap).toBeLessThanOrEqual(12);
  expect(portGeometry.bottomGap).toBeLessThanOrEqual(14);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
  await page.locator(".settings-section").filter({has: portCard}).screenshot({path: testInfo.outputPath("dns-proxy-cards.png")});
  await page.locator("#dns-proxy-status").scrollIntoViewIfNeeded();
  await page.screenshot({path: testInfo.outputPath("dns-proxy-settings.png")});
});

test("one domain check shows matching rules and retains them when DNS lookup fails", async ({page}, testInfo) => {
  const requests = [];
  await page.route("**/api/tools/check-ip", route => {
    const {target} = route.request().postDataJSON();
    requests.push(target);
    const excluded = target === "private.example.test";
    return route.fulfill({json: {
      target, addresses: excluded ? [] : ["192.0.2.10"],
      domain_rule: {domain: target, scope: excluded ? "active" : "saved", action: excluded ? "exclude" : "include",
        include_rule: excluded ? null : "*.example.test", exclude_rule: excluded ? "regex:^private\\.example\\.test$" : null},
      lookup_error: excluded ? "DNS server did not respond" : null,
      results: excluded ? [] : [{result: {ip: "192.0.2.10", matched: true, decision: "included", confirmed: true,
        routes: ["192.0.2.0/24"], sources: [], snapshot_applied_at_unix: 1700000000}}],
    }});
  });
  await navigate(page, "lists");
  await page.locator('[data-list="include-domains"]').click();
  await expect(page.locator("#list-hint")).toContainText("regex:");
  await expect(page.locator("#domain-rule-test")).toHaveCount(0);
  await navigate(page, "check");
  await expect(page.getByRole("heading", {name: "Check IP / domain", exact: true})).toHaveCount(1);
  await expect(page.locator("#check form")).toHaveCount(1);
  await page.getByLabel("Check IP / domain", {exact: true}).fill("video.example.test");
  await page.locator("#check-ip-submit").click();
  const result = page.locator("#check-ip-result");
  await expect(result.locator(".domain-rule-result")).toContainText("Saved manual rules: matched an include rule");
  await expect(result.locator(".domain-rule-result")).toContainText("Include rule: *.example.test");
  await expect(result.locator(".decision-banner")).toContainText("Included in active routes");
  await expect(result.locator(".route-list")).toContainText("192.0.2.0/24");
  await page.locator("#check-ip-input").fill("private.example.test");
  await page.locator("#check-ip-submit").click();
  await expect(result.locator(".domain-rule-result")).toContainText("Applied rules: matched an exclude rule");
  await expect(result.locator(".domain-rule-result")).toContainText("Exclude rule: regex:^private\\.example\\.test$");
  await expect(result.locator(".status-pill")).toHaveText("Could not resolve the domain");
  await expect(result.locator(".error-inline")).toHaveText("DNS server did not respond");
  await expect(result.locator(".decision-banner")).toHaveCount(0);
  await expect(result).not.toContainText("0/0 matched");
  await language(page, "ru");
  await expect(page.getByRole("heading", {name: "Проверить IP / домен", exact: true})).toHaveCount(1);
  await expect(result.locator(".domain-rule-result")).toContainText("Применённые правила: совпало исключающее правило");
  await expect(result.locator(".status-pill")).toHaveText("Не удалось получить IP домена");
  await expect(page.getByLabel("Проверить IP / домен", {exact: true})).toHaveValue("private.example.test");
  expect(requests).toEqual(["video.example.test", "private.example.test"]);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
  await page.screenshot({path: testInfo.outputPath("domain-check.png"), fullPage: true});
});

test("copy works without Clipboard API and restores focus", async ({page}) => {
  await navigate(page, "lists");
  await page.locator('[data-list="urls"]').click();
  const button = page.locator("#list-tiles [data-copy]").first();
  const value = await button.getAttribute("data-copy");
  await page.evaluate(() => Object.defineProperty(navigator, "clipboard", {value: undefined, configurable: true}));
  await button.focus();
  await button.click();
  await expect(button).toHaveText("Copied");
  await expect(button).toBeFocused();
  await expect(page.locator('textarea[readonly]')).toHaveCount(0);
  await page.locator("#list-search").focus();
  await page.keyboard.press("Control+V");
  await expect(page.locator("#list-search")).toHaveValue(value);
});

test("live IP checks show DNS origin and stay accurate in both languages", async ({page}) => {
  await page.route("**/api/tools/check-ip", route => route.fulfill({json: {result: {
    ip: "192.0.2.10", live: true, matched: true, decision: "included", confirmed: false,
    routes: ["192.0.2.10/32"], sources: [],
    dns_origin: {domain: "video.example.test", rule: "*.example.test", added_at: 1700000000},
  }}}));
  await navigate(page, "check");
  await page.locator("#check-ip-input").fill("192.0.2.10");
  await page.locator("#check-ip-submit").click();
  const result = page.locator("#check-ip-result");
  await expect(result.getByRole("heading", {name: "Routes in BIRD", exact: true})).toBeVisible();
  await expect(result.locator(".decision-banner")).toContainText("Included in active routes");
  await expect(result.locator(".kv-grid")).toContainText("Route from a DNS reply");
  await expect(result.locator(".kv-grid")).toContainText("video.example.test");
  await expect(result.locator(".kv-grid")).toContainText("Matching rule: *.example.test");
  await expect(result.locator(".kv-grid")).toContainText("Added:");
  await expect(result.locator("p.muted")).toHaveText("Result from the current BIRD routing table.");
  await expect(result).not.toContainText("Source history is unavailable");
  await expect(result).not.toContainText("Confirmed route snapshot");
  await language(page, "ru");
  await expect(result.getByRole("heading", {name: "Маршруты в BIRD", exact: true})).toBeVisible();
  await expect(result.locator(".kv-grid")).toContainText("Сработавшее правило: *.example.test");
  await expect(result.locator("p.muted")).toHaveText("Результат из текущей таблицы маршрутов BIRD.");
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
});

test("failed IP checks stay failed when changing language", async ({page}) => {
  await navigate(page, "check");
  await page.locator("#check-ip-input").fill("192.0.2.1");
  await page.locator("#check-ip-submit").click();
  await expect(page.locator("#check-ip-result")).toContainText("192.0.2.1");
  await page.locator("#check-ip-input").fill("invalid target");
  await page.locator("#check-ip-submit").click();
  await expect(page.locator("#check-ip-result")).toContainText("target must be an IPv4 address or domain");
  await language(page, "ru");
  await expect(page.locator("#check-ip-result")).toContainText("target must be an IPv4 address or domain");
  await expect(page.locator("#check-ip-result")).not.toContainText("192.0.2.1");
  await expect(page.locator("#check-ip-result .status-pill")).toHaveText("Ошибка");
  await expect(page.locator("#check-ip-submit")).toHaveText("Проверить");
  await language(page, "en");
  await expect(page.locator("#check-ip-submit")).toHaveText("Check");
  await expect(page.locator("#check-ip-result .status-pill")).toHaveText("Failed");
});

test("Google controls stay separate and all localized list tabs fit phones", async ({page}) => {
  const status = await (await page.request.get("/api/status")).json();
  await page.route("**/api/status", route => route.fulfill({json: {...status, status: {...status.status, sources: [{kind: "google", name: "goog.json", status: "fresh", routes: 100, bytes: 1000}]}}}));
  await page.locator("#refresh-btn").click();
  await language(page, "ru");
  await navigate(page, "lists");
  await page.locator('[data-list="google-ranges"]').click();
  const left = await page.locator(".google-ranges-toggle-card").boundingBox();
  const right = await page.locator(".google-ranges-status-card").boundingBox();
  expect(Math.min(left.x+left.width,right.x+right.width)>Math.max(left.x,right.x) && Math.min(left.y+left.height,right.y+right.height)>Math.max(left.y,right.y)).toBe(false);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.locator('[data-list="urls"]').click();
  await page.locator("#list-search").fill("no-such-source");
  await expect(page.locator("#list-count")).toContainText("Показано: 0");
  await expect(page.locator("#list-tiles .list-card:visible")).toHaveCount(0);
  await page.setViewportSize({width: 901, height: 1000});
  expect((await page.locator("#add-list-input").boundingBox()).width).toBeGreaterThan(200);
});

test("all list tabs keep one panel and shorten display paths without losing country controls", async ({page}) => {
  const files = {urls: "lists.txt", asns: "include-asns.txt", countries: "include-countries.txt", "include-domains": "include-domains.txt", "exclude-domains": "exclude-domains.txt", "domain-list-urls": "domain-list-urls.txt"};
  await page.route("**/api/lists/*", async route => {
    if (route.request().method() !== "GET") return route.continue();
    const response = await route.fetch();
    const data = await response.json();
    const name = new URL(route.request().url()).pathname.split("/").pop();
    await route.fulfill({response, json: {...data, path: `/etc/bird/config/${files[name]}`}});
  });
  await navigate(page, "lists");
  for (const lang of ["ru", "en"]) {
    await language(page, lang);
    for (const name of [...Object.keys(files).filter(name => name !== "domain-list-urls"), "google-ranges"]) {
      await page.locator(`[data-list="${name}"]`).click();
      const panel = page.locator("#lists > .editor-panel");
      await expect(panel).toBeVisible();
      await expect(page.locator("#lists .panel:visible")).toHaveCount(1);
      if (name !== "google-ranges") {
        await expect(panel.locator("#list-title")).toHaveText(`/config/${files[name]}`);
        await expect(panel.locator("#list-filters")).toBeVisible();
        await expect(panel.locator("#dry-after-save-btn")).toBeVisible();
      } else {
        await expect(panel.locator("#list-include-google-ranges")).toBeAttached();
        await expect(panel.locator("#add-list-form")).toBeHidden();
        await expect(panel.locator("#dry-after-save-btn")).toBeHidden();
      }
      if (name === "countries") await expect(panel.locator(".country-card")).toHaveCount(24);
      if (name === "include-domains") await expect(panel.locator(".domain-list-source-head h2")).toHaveText("/config/domain-list-urls.txt");
      const layout = await panel.evaluate(panel => {
        const title = panel.querySelector("#list-title").getBoundingClientRect();
        const styles = getComputedStyle(panel);
        return {titleInset: title.top - panel.getBoundingClientRect().top, padding: parseFloat(styles.paddingTop), border: parseFloat(styles.borderTopWidth), width: document.documentElement.scrollWidth, viewport: innerWidth};
      });
      expect(layout.titleInset).toBeCloseTo(layout.padding + layout.border, 0);
      expect(layout.width).toBeLessThanOrEqual(layout.viewport);
    }
  }
  await page.locator('[data-list="countries"]').click();
  await page.locator('.country-card:has([data-country-code="RU"])').click();
  await expect.poll(async () => (await (await page.request.get("/api/lists/countries")).json()).content).toContain("RU");
  await page.locator("#country-selected").check();
  await expect(page.locator(".country-card:visible")).toHaveCount(1);
  await expect(page.locator("#list-count")).toContainText("1 / 24");
});

test("URL source cards align within desktop rows and retain natural mobile heights", async ({page}, testInfo) => {
  const mobile = testInfo.project.name === "mobile";
  if (!mobile) await page.setViewportSize({width: 1800, height: 1100});
  const entries = [
    ["Long URL", `https://example.test/${"nested-segment/".repeat(10)}routes.txt`],
    ["Short URL", "https://example.org/a.txt"],
    ["Another long URL", `https://example.test/${"another-segment/".repeat(10)}domains.txt`],
    ["Another short URL", "https://example.org/b.txt"],
  ];
  const content = entries.map(([name, url]) => `${name} | ${url}`).join("\n") + "\n";
  for (const list of ["urls", "domain-list-urls"]) expect((await page.request.put(`/api/lists/${list}`, {data: {content}})).ok()).toBeTruthy();
  const status = await (await page.request.get("/api/status")).json();
  const sources = ["url", "domain-list-url"].flatMap(kind => entries.map(([name, url]) => ({kind, name, url, status: "fresh", routes: 123, bytes: 1024})));
  await page.route("**/api/status", route => route.fulfill({json: {...status, status: {...status.status, sources}}}));
  await page.locator("#refresh-btn").click();
  await navigate(page, "lists");
  await language(page, "ru");
  for (const [tab, selector] of [["urls", "#list-tiles"], ["include-domains", ".domain-list-url-cards"]]) {
    await page.locator(`[data-list="${tab}"]`).click();
    const grid = page.locator(selector);
    await expect(grid.locator(":scope > .list-card")).toHaveCount(4);
    const cards = await grid.locator(":scope > .list-card").evaluateAll(items => items.map(card => {
      const box = card.getBoundingClientRect();
      const stats = card.querySelector(".list-card-stats").getBoundingClientRect();
      const actions = card.querySelector(".list-card-actions").getBoundingClientRect();
      return {x: box.x, top: box.top, bottom: box.bottom, height: box.height, statsTop: stats.top, statsBottom: stats.bottom, actionsTop: actions.top,
        previewHeight: card.querySelector(".url-preview").getBoundingClientRect().height};
    }));
    if (mobile) {
      expect(cards[1].x).toBeCloseTo(cards[0].x, 0);
      expect(cards[1].top).toBeGreaterThan(cards[0].bottom);
      expect(cards[1].previewHeight).toBeLessThan(cards[0].previewHeight);
    } else {
      for (const index of [0, 2]) {
        expect(cards[index + 1].x).toBeGreaterThan(cards[index].x);
        for (const key of ["top", "bottom", "height", "statsTop", "statsBottom", "actionsTop", "previewHeight"]) {
          expect(cards[index + 1][key], `${tab}: ${key}`).toBeCloseTo(cards[index][key], 0);
        }
      }
    }
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
    await grid.screenshot({path: testInfo.outputPath(`${tab}-aligned-cards.png`)});
  }
});

test("preview applies the reviewed snapshot even when the source later changes", async ({page, request}) => {
  await request.post("/__test/source", {data: {content: "198.51.100.0/24\n"}});
  await page.locator("[data-preview-routes]").first().click();
  await expect(page.locator("#preview-diff")).toContainText("198.51.100.0/24");
  await expect(page.locator("#preview-diff")).toContainText("192.0.2.0/24");
  await request.post("/__test/source", {data: {content: "203.0.113.0/24\n"}});
  await page.locator("#apply-preview-btn").click();
  await expect.poll(async () => (await (await page.request.get("/api/routes")).text())).toContain("198.51.100.0/24");
  await navigate(page, "routes");
  await expect(page.locator("#routes-view")).toContainText("198.51.100.0/24");
  await expect(page.locator("#routes-view")).not.toContainText("203.0.113.0/24");
  await navigate(page, "check");
  await page.locator("#check-ip-input").fill("198.51.100.1");
  await page.locator("#check-ip-submit").click();
  await expect(page.locator("#check-ip-result")).toContainText("Confirmed route snapshot");
  await expect(page.locator("#check-ip-result")).toContainText("Example");
});

test("list edits have reviewable history and can be restored", async ({page}) => {
  await navigate(page, "lists");
  await page.locator(".raw-list-editor summary").click();
  const previous = await page.locator("#list-editor").inputValue();
  await page.locator("#list-editor").fill(previous + "# browser edit\n");
  await page.locator("#save-list-btn").click();
  await expect(page.locator("#list-save-status")).toContainText("Saved");
  await navigate(page, "backups");
  await expect(page.locator("[data-history-version]").first()).toBeVisible();
  await page.locator("[data-history-version]").first().click();
  await expect(page.locator("#history-review")).toContainText("-# browser edit");
  await page.locator("#restore-list-btn").click();
  await expect(page.locator("#backup-status")).toContainText("List restored");
  await navigate(page, "lists");
  await expect(page.locator("#list-editor")).toHaveValue(previous);
});

test("empty history explains when copies are created and loading errors stay visible", async ({page}) => {
  await navigate(page, "backups");
  await page.locator("#history-list").selectOption("exclude-domains");
  await expect(page.locator("#history-versions")).toContainText("This list has no saved versions yet");
  await expect(page.locator('[data-i18n="listHistoryHint"]')).toContainText("previous version is saved automatically");
  await expect(page.locator("#history-review")).toBeHidden();
  await page.route("**/api/backups/lists?*", route => route.fulfill({status: 500, json: {error: "History storage unavailable"}}));
  await page.locator("#load-history-btn").click();
  await expect(page.locator("#history-versions")).toContainText("History storage unavailable");
  await expect(page.locator("#history-versions")).not.toContainText("no saved versions");
  await expect(page.locator("#restore-list-btn")).toBeHidden();
  await page.unroute("**/api/backups/lists?*");
  await page.locator("#load-history-btn").click();
  await expect(page.locator("#history-versions")).toContainText("This list has no saved versions yet");
  await language(page, "ru");
  await expect(page.locator("#history-list option:checked")).toHaveText("Исключаемые домены");
  await expect(page.locator("#history-versions")).toContainText("Для этого списка");
});

test("navigation collapses on phones and expanded rows fit narrow screens", async ({page}, testInfo) => {
  await language(page, "ru");
  for (const width of testInfo.project.name === "mobile" ? [390, 320] : [1366, 901]) {
    await page.setViewportSize({width, height: 1000});
    if (width <= 900) {
      expect((await page.locator("#sidebar").boundingBox()).height).toBeLessThan(90);
      await openMenu(page);
    }
    const layout = await page.locator("#sidebar").evaluate(sidebar => {
      const nav=sidebar.querySelector("nav");
      const rows=[...nav.querySelectorAll(".nav-item")].map(button => {
        const box=button.getBoundingClientRect(), style=getComputedStyle(button);
        return {left:box.left,right:box.right,top:box.top,bottom:box.bottom,height:box.height,radius:style.borderRadius,overflow:button.scrollWidth>button.clientWidth};
      });
      return {sidebar:sidebar.getBoundingClientRect().toJSON(), nav:nav.getBoundingClientRect().toJSON(), rows, overflow:document.documentElement.scrollWidth>innerWidth};
    });
    expect(layout.overflow).toBe(false);
    expect(layout.nav.left).toBeCloseTo(layout.sidebar.left, 0);
    expect(layout.nav.right).toBeCloseTo(layout.sidebar.right - (width>900 ? 1 : 0), 0);
    for (const row of layout.rows) {
      expect(row.radius).toBe("0px");
      expect(row.height).toBeGreaterThanOrEqual(44);
      expect(row.overflow).toBe(false);
    }
    const columns=width>900 ? 1 : 2;
    for(let index=columns;index<layout.rows.length;index++) expect(layout.rows[index].top).toBeCloseTo(layout.rows[index-columns].bottom, 0);
    if(columns===2) expect(layout.rows[1].left).toBeCloseTo(layout.rows[0].right,0);
    if (width <= 900) await page.locator("#menu-toggle").click();
  }
  await navigate(page, "backups");
  await page.locator("#history-list").selectOption("exclude-domains");
  await expect(page.locator("#history-versions")).toContainText("Для этого списка");
  const clipped=await page.locator(".topbar h1, .top-actions button, #backups .button-link, .backup-transfer, #choose-config-btn, #history-list, #load-history-btn").evaluateAll(elements=>elements.filter(element=>{
    const box=element.getBoundingClientRect();
    return box.left<0 || box.right>innerWidth || element.scrollWidth>element.clientWidth+1;
  }).map(element=>element.id||element.className||element.tagName));
  expect(clipped).toEqual([]);
  await page.screenshot({path:testInfo.outputPath("sections-and-history.png"), fullPage:true});
});

test("configuration import requires review and invalid uploads preserve settings", async ({page}) => {
  await navigate(page, "backups");
  const exported = await (await page.request.get("/api/backups/export")).json();
  exported.settings.FETCH_TIMEOUT = "45";
  const upload = async backup => {
    const choosing = page.waitForEvent("filechooser");
    await page.locator("#choose-config-btn").click();
    await (await choosing).setFiles({name: "config.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(backup))});
    await expect(page.locator("#config-file-name")).toHaveText("config.json");
  };
  await upload(exported);
  await expect(page.locator("#config-import-review")).toContainText("FETCH_TIMEOUT");
  await expect(page.locator("#restore-config-btn")).toBeVisible();
  expect((await (await page.request.get("/api/settings")).json()).values.FETCH_TIMEOUT).toBe("30");
  await page.locator("#restore-config-btn").click();
  await expect(page.locator("#backup-status")).toContainText("Configuration restored");
  expect((await (await page.request.get("/api/settings")).json()).values.FETCH_TIMEOUT).toBe("45");
  exported.settings.MT_IP = "bad";
  await upload(exported);
  await expect(page.locator("#backup-status")).toContainText("MT_IP must be a valid");
  await expect(page.locator("#restore-config-btn")).toBeHidden();
});

test("update screen survives a status disconnect and displays an expired session after restart", async ({page, request}) => {
  await page.locator("#open-updates-btn").click();
  let calls = 0;
  await page.route("**/api/update/status?force=1", route => ++calls === 1 ? route.abort("connectionreset") : route.continue());
  await page.locator("#check-updates-btn").click();
  await expect(page.locator("#update-summary")).toContainText("Update check failed");
  await page.locator("#check-updates-btn").click();
  await expect(page.locator("#update-summary")).toContainText("newer release");
  await request.post("/__test/expire");
  await page.reload();
  await expect(page.locator("#login-view")).toBeVisible();
});

test("an interrupted update launch keeps polling and returns to login after session loss", async ({page, request}) => {
  const available = await (await page.request.get("/api/update/status")).json();
  let interrupted = false;
  let launches = 0;
  await page.route("**/api/update/status*", route => interrupted ? route.continue() : route.fulfill({json: {
    ...available, updater_ok: true, updater_error: "", apply_available: true,
  }}));
  await page.route("**/api/update/apply", async route => {
    launches++;
    interrupted = true;
    await request.post("/__test/expire");
    await route.abort("connectionreset");
  });
  await page.locator("#open-updates-btn").click();
  await page.locator("#check-updates-btn").click();
  await expect(page.locator("#apply-update-btn")).toBeVisible();
  await page.locator("#apply-update-btn").click();
  await expect(page.locator("#login-view")).toBeVisible({timeout: 10000});
  expect(launches).toBe(1);
});
