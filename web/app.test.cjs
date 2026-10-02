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
function link(value) {
  const query = new URLSearchParams({
    type: "xhttp", host: "", path: "/api/v1/", mode: "auto", extra: value,
    security: "tls", sni: "test.example.invalid", alpn: "h2", fp: "safari",
  });
  return `vless://11111111-1111-4111-8111-111111111111@test.example.invalid:443?${query}#Резерв`;
}

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

test("full config includes the decoded XHTTP settings", () => {
  context.fixtureTemplate = JSON.parse(fs.readFileSync(path.join(__dirname, "../tools/happ-two-vless.json"), "utf8"));
  context.fixtureLink = link(encodeURIComponent(extraJson));
  const config = JSON.parse(vm.runInContext(`
    template = fixtureTemplate;
    state = defaultState();
    state.workKey = "vless://22222222-2222-4222-8222-222222222222@work.example.invalid:443?security=tls";
    state.foreign[0].key = fixtureLink;
    JSON.stringify(buildConfig());
  `, context));
  assert.deepEqual(config.outbounds[0].streamSettings.xhttpSettings.extra, extra);
  assert.equal(config.outbounds[0].tag, "VLESS-Заграница");
  assert.deepEqual(config.routing.rules, context.fixtureTemplate.routing.rules);
});
