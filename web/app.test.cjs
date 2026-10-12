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
