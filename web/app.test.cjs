"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { test } = require("node:test");

// Load the browser code without starting the UI or accessing saved user keys.
const context = vm.createContext({ URL, atob, fetch: () => new Promise(() => {}) });
vm.runInContext(fs.readFileSync(path.join(__dirname, "app.js"), "utf8"), context);
const parse = (link) => JSON.parse(JSON.stringify(context.parseVless(link, "test")));
const extra = { xmux: { cMaxLifetimeMs: "180000-300000", cMaxReuseTimes: "0", maxConcurrency: "16-32" } };
const extraJson = JSON.stringify(extra, null, 2);
function link(value, options = {}) {
  const query = new URLSearchParams({
    type: "xhttp", host: "", path: "/api/v1/", mode: "auto", extra: value,
    security: "tls", sni: "test.example.invalid", alpn: "h2", fp: "safari",
    ...options,
  });
  return `vless://11111111-1111-4111-8111-111111111111@test.example.invalid:443?${query}#Резерв`;
}

const pinnedCerts = `${"ab".repeat(32)},${"cd".repeat(32)}`;
const providerExtra = {
  scMaxEachPostBytes: 40000, scMinPostsIntervalMs: 1, uplinkChunkSize: 16000,
  uplinkDataPlacement: "header", uplinkHTTPMethod: "GET",
  xmux: { cMaxReuseTimes: 0, hKeepAlivePeriod: 0, hMaxRequestTimes: "100-200",
    hMaxReusableSecs: "300-600", maxConcurrency: "0", maxConnections: 2 },
};
const pinnedLink = () => link(encodeURIComponent(JSON.stringify(providerExtra, null, 2)), {
  host: "cdn.example.invalid", path: "/cdnb1/", mode: "packet-up", fp: "firefox",
  pcs: pinnedCerts, pcn: "certificate.example.invalid",
});

test("XHTTP provider exports preserve certificate pins, names and extra", () => {
  const stream = parse(pinnedLink()).streamSettings;
  assert.deepEqual(stream.tlsSettings, {
    serverName: "test.example.invalid", fingerprint: "firefox", allowInsecure: false,
    alpn: ["h2"], pinnedPeerCertSha256: pinnedCerts, verifyPeerCertByName: "certificate.example.invalid",
  });
  assert.deepEqual(stream.xhttpSettings, {
    host: "cdn.example.invalid", path: "/cdnb1/", mode: "packet-up", extra: providerExtra,
  });
});

test("TLS certificate options accept standard aliases, lists and OpenSSL hashes", () => {
  for (const options of [
    { pcn: "one.example.invalid,two.example.invalid" },
    { vcn: "one.example.invalid,two.example.invalid" },
    { pcn: "one.example.invalid,two.example.invalid", vcn: "one.example.invalid,two.example.invalid" },
    { pcn: "", vcn: "one.example.invalid,two.example.invalid" },
  ]) {
    const pcs = "AB:".repeat(31) + "AB";
    const tls = parse(link("", { ...options, pcs })).streamSettings.tlsSettings;
    assert.equal(tls.verifyPeerCertByName, "one.example.invalid,two.example.invalid");
    assert.equal(tls.pinnedPeerCertSha256, pcs);
  }
  const tls = parse(link("", { pcs: "", pcn: "", vcn: "" })).streamSettings.tlsSettings;
  assert.equal(tls.pinnedPeerCertSha256, undefined);
  assert.equal(tls.verifyPeerCertByName, undefined);
});

test("invalid TLS certificate options and non-TLS uses are rejected", () => {
  for (const pcs of ["ab", "gg".repeat(32), `${pinnedCerts},`, `,${pinnedCerts}`]) {
    assert.throws(() => parse(link("", { pcs })), /pcs должен содержать SHA-256/);
  }
  assert.throws(() => parse(link("", { pcn: "one.example.invalid", vcn: "two.example.invalid" })), /pcn и vcn/);
  assert.throws(() => parse(link("", { security: "none", pcs: pinnedCerts, pcn: "one.example.invalid" })), /Неподдерживаемые параметры/);
});

test("XHTTP extra accepts ordinary and doubly encoded exports", () => {
  for (const value of [extraJson, encodeURIComponent(extraJson)]) {
    const stream = parse(link(value)).streamSettings;
    assert.deepEqual(stream.xhttpSettings, { path: "/api/v1/", mode: "auto", extra });
    assert.equal(stream.tlsSettings.fingerprint, "safari");
    assert.deepEqual(stream.tlsSettings.alpn, ["h2"]);
  }
});

test("exact provider encoding with unescaped colons and commas is accepted", () => {
  const exportedExtra = "%257B%250A%2520%2520%2522xmux%2522%2520:%2520%257B%250A%2520%2520%2520%2520%2522cMaxLifetimeMs%2522%2520:%2520%2522180000-300000%2522,%250A%2520%2520%2520%2520%2522cMaxReuseTimes%2522%2520:%2520%25220%2522,%250A%2520%2520%2520%2520%2522maxConcurrency%2522%2520:%2520%252216-32%2522%250A%2520%2520%257D%250A%257D";
  const uri = link("").replace("extra=&", `extra=${exportedExtra}&`);
  assert.deepEqual(parse(uri).streamSettings.xhttpSettings.extra, extra);
});

test("extra preserves percent escapes, plus signs and Unicode inside JSON", () => {
  const expected = { path: "/a%2Fb%25", label: "Резерв + 100%", nested: { value: "%ZZ" } };
  for (const value of [JSON.stringify(expected), encodeURIComponent(JSON.stringify(expected))]) {
    assert.deepEqual(parse(link(value)).streamSettings.xhttpSettings.extra, expected);
  }
});

test("extra rejects invalid JSON, non-objects and excess encoding", () => {
  for (const value of ["[]", "null", '"text"', "1", "{bad}", "%ZZ", "%7B%FF%7D", '{"x":NaN}', encodeURIComponent(encodeURIComponent(extraJson))]) {
    assert.throws(() => parse(link(value)), /XHTTP extra должен быть JSON-объектом/);
    assert.throws(() => parse(link(encodeURIComponent(value))), /XHTTP extra должен быть JSON-объектом/);
  }
});

test("full config includes the decoded XHTTP and certificate settings", () => {
  context.fixtureTemplate = JSON.parse(fs.readFileSync(path.join(__dirname, "../tools/happ-two-vless.json"), "utf8"));
  context.fixtureLink = pinnedLink();
  const config = JSON.parse(vm.runInContext(`
    template = fixtureTemplate;
    state = defaultState();
    state.workKey = "vless://22222222-2222-4222-8222-222222222222@work.example.invalid:443?security=tls";
    state.foreign[0].key = fixtureLink;
    JSON.stringify(buildConfig());
  `, context));
  assert.deepEqual(config.outbounds[0].streamSettings, parse(pinnedLink()).streamSettings);
  assert.equal(config.outbounds[0].tag, "VLESS-Заграница");
  assert.deepEqual(config.routing.rules, context.fixtureTemplate.routing.rules);
});

test("saved keys and custom routes survive the DNS migration", () => {
  const legacyRules = [
    { type: "field", inboundTag: ["internal-dns"], domain: ["full:dns.google"], outboundTag: "direct" },
    { type: "field", inboundTag: ["internal-dns"], ip: ["8.8.8.8"], outboundTag: "direct" },
    { type: "field", inboundTag: ["internal-dns"], outboundTag: "VLESS-Заграница" },
    { type: "field", domain: ["full:custom.example.invalid"], outboundTag: "VLESS-Работа" },
    { type: "field", network: "tcp,udp", outboundTag: "VLESS-Заграница" },
  ];
  const saved = {
    workKey: "saved-work-key", workNote: "Работа", title: "Мой профиль", description: "Описание",
    foreign: [{ key: "saved-foreign-key", note: "Резерв" }],
    rules: JSON.parse(JSON.stringify(context.parseRoutesText(JSON.stringify(legacyRules)))),
  };
  context.localStorage = { getItem: () => JSON.stringify(saved) };
  context.fixtureTemplate = JSON.parse(fs.readFileSync(path.join(__dirname, "../tools/happ-two-vless.json"), "utf8"));
  const result = JSON.parse(vm.runInContext(`
    template = fixtureTemplate;
    state = defaultState();
    const restored = loadSaved();
    JSON.stringify({ restored, state });
  `, context));
  assert.equal(result.restored, true);
  assert.deepEqual(result.state, {
    ...saved,
    foreign: saved.foreign.map(item => ({ ...item, enabled: true })),
    rules: [
      { inbound: "dns-direct", kind: "any", values: "", destination: "direct" },
      { inbound: "dns-vpn", kind: "any", values: "", destination: "foreign" },
      ...saved.rules.slice(3),
    ],
  });
  const migratedAgain = JSON.parse(JSON.stringify(context.updateDnsRoutes(result.state.rules)));
  assert.deepEqual(migratedAgain, result.state.rules);
});

test("route imports add DNS paths before catch-all and retain other inbound tags", () => {
  const imported = context.parseRoutesText(JSON.stringify([
    { type: "field", inboundTag: ["internal-dns", "custom-in"], domain: ["full:custom.example.invalid"], outboundTag: "direct" },
    { type: "field", network: "tcp,udp", outboundTag: "VLESS-Заграница" },
  ]));
  const updated = JSON.parse(JSON.stringify(context.updateDnsRoutes(imported)));
  assert.deepEqual(updated.map(row => row.inbound), ["dns-direct", "dns-vpn", "custom-in", ""]);
  assert.equal(updated[2].values, "full:custom.example.invalid");
  assert.equal(updated[3].kind, "network");
});

test("DNS routes use the foreign balancer with multiple keys", () => {
  const config = JSON.parse(vm.runInContext(`
    state = defaultState();
    state.workKey = "vless://22222222-2222-4222-8222-222222222222@work.example.invalid:443?security=tls";
    state.foreign = [{ key: fixtureLink, note: "" }, { key: fixtureLink, note: "" }];
    JSON.stringify(buildConfig());
  `, context));
  assert.deepEqual(config.routing.rules.slice(0, 2), [
    { type: "field", inboundTag: ["dns-direct"], outboundTag: "direct" },
    { type: "field", inboundTag: ["dns-vpn"], balancerTag: "Заграница-автовыбор" },
  ]);
  assert.equal(config.dns.disableFallbackIfMatch, true);
  assert.equal(config.dns.disableFallback, false);
  assert.equal(config.dns.enableParallelQuery, false);
});

test("excluded foreign keys are ignored and routing follows the active server count", () => {
  context.fixtureTemplate = JSON.parse(fs.readFileSync(path.join(__dirname, "../tools/happ-two-vless.json"), "utf8"));
  context.fixtureLink = pinnedLink();
  const configs = JSON.parse(vm.runInContext(`(() => {
    template = fixtureTemplate;
    state = defaultState();
    state.workKey = "vless://22222222-2222-4222-8222-222222222222@work.example.invalid:443?security=tls";
    state.foreign = [
      { key: "invalid disabled key", note: "Не удалять", enabled: false },
      { key: fixtureLink, note: "Первый", enabled: true },
      { key: "", note: "Заполнить позже", enabled: false },
      { key: fixtureLink.replaceAll("test.example.invalid", "second.example.invalid"), note: "Второй", enabled: true },
    ];
    const multiple = buildConfig();
    state.foreign[1].enabled = false;
    const single = buildConfig();
    state.foreign[3].enabled = false;
    const none = buildConfig();
    state.foreign[1].enabled = true;
    state.foreign[3].enabled = true;
    const restored = buildConfig();
    return JSON.stringify({ multiple, single, none, restored, foreign: state.foreign });
  })()`, context));
  const { multiple, single, none, restored, foreign } = configs;
  assert.deepEqual(multiple.outbounds.filter(x => x.protocol === "vless").map(x => x.tag), [
    "VLESS-Заграница-1", "VLESS-Заграница-2", "VLESS-Работа",
  ]);
  assert.equal(multiple.routing.balancers[0].fallbackTag, "VLESS-Заграница-1");
  assert.equal(multiple.routing.rules[1].balancerTag, "Заграница-автовыбор");
  assert.deepEqual(single.outbounds.filter(x => x.protocol === "vless").map(x => x.tag), [
    "VLESS-Заграница", "VLESS-Работа",
  ]);
  assert.equal(single.outbounds[0].settings.vnext[0].address, "second.example.invalid");
  assert.equal(single.routing.balancers, undefined);
  assert.equal(single.observatory, undefined);
  assert.ok(single.routing.rules.every(rule => !rule.balancerTag));
  assert.equal(single.routing.rules[1].outboundTag, "VLESS-Заграница");
  assert.equal(none, null);
  assert.deepEqual(restored, multiple);
  assert.deepEqual(foreign[0], { key: "invalid disabled key", note: "Не удалять", enabled: false });
});

test("enabled foreign keys still require valid nonempty links", () => {
  context.fixtureTemplate = JSON.parse(fs.readFileSync(path.join(__dirname, "../tools/happ-two-vless.json"), "utf8"));
  const config = vm.runInContext(`
    template = fixtureTemplate;
    state = defaultState();
    state.workKey = "vless://22222222-2222-4222-8222-222222222222@work.example.invalid:443?security=tls";
    state.foreign = [{ key: "", note: "", enabled: true }];
    buildConfig();
  `, context);
  assert.equal(config, null);
  assert.throws(() => vm.runInContext(`
    state.foreign[0].key = "invalid enabled key";
    buildConfig();
  `, context), /VLESS|vless/);
});

test("saved foreign switches retain false and migrate missing values to true", () => {
  context.fixtureTemplate = JSON.parse(fs.readFileSync(path.join(__dirname, "../tools/happ-two-vless.json"), "utf8"));
  const saved = {
    workKey: "saved-work-key", workNote: "Работа", title: "Мой профиль", description: "Описание",
    foreign: [
      { key: "saved-disabled-key", note: "Резерв", enabled: false },
      { key: "saved-enabled-key", note: "Основной", enabled: true },
      { key: "saved-legacy-key", note: "Старый" },
    ],
    rules: [],
  };
  context.localStorage = { getItem: () => JSON.stringify(saved) };
  const result = JSON.parse(vm.runInContext(`
    template = fixtureTemplate;
    state = defaultState();
    JSON.stringify({ restored: loadSaved(), state });
  `, context));
  assert.equal(result.restored, true);
  assert.deepEqual(result.state.foreign, saved.foreign.map(item => ({ ...item, enabled: item.enabled !== false })));
  saved.foreign[0].enabled = "false";
  assert.equal(vm.runInContext("loadSaved()", context), false);
});

test("both DNS chains exhaust Google paths before trying Cloudflare", () => {
  const { dns } = JSON.parse(fs.readFileSync(path.join(__dirname, "../tools/happ-two-vless.json"), "utf8"));
  const categories = ["geosite:category-ru", "geosite:apple", "geosite:microsoft", "geosite:android"];
  for (const category of [...categories, null]) {
    const priority = dns.servers.filter(server => server.domains?.includes(category));
    const fallback = dns.servers.filter(server => !priority.includes(server) && !server.skipFallback);
    const selected = dns.disableFallbackIfMatch && priority.length ? priority : [...priority, ...fallback];
    assert.deepEqual(selected.map(server => new URL(server.address).hostname), [
      "dns.google", "dns.google", "cloudflare-dns.com", "cloudflare-dns.com",
    ]);
    const first = category ? "dns-direct" : "dns-vpn";
    const second = category ? "dns-vpn" : "dns-direct";
    assert.deepEqual(selected.map(server => server.tag), [first, second, first, second]);
  }
});
