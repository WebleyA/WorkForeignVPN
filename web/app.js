"use strict";

const STORAGE_KEY = "happ-config-studio-v1";
const WORK_TAG = "VLESS-Работа";
const FOREIGN_TAG = "VLESS-Заграница";
const BALANCER_TAG = "Заграница-автовыбор";
const FOREIGN_PREFIX = "VLESS-Заграница-";
const DEFAULT_TITLE = "Lex — VLESS-Работа + VLESS-Заграница";
const DEFAULT_DESCRIPTION = "VLESS | TCP | TLS | JSON";
const $ = (selector) => document.querySelector(selector);
const clone = (value) => JSON.parse(JSON.stringify(value));

let template;
let state;
let latestJson = "";
let draggedIndex = null;

function defaultState() {
  return {
    workKey: "", workNote: "", title: DEFAULT_TITLE, description: DEFAULT_DESCRIPTION,
    foreign: [{ key: "", note: "" }],
    rules: clone(template.routing.rules).map(ruleToRow),
  };
}

function ruleToRow(rule) {
  const kind = ["domain", "ip", "network"].find(key => key in rule) || "any";
  return {
    inbound: (rule.inboundTag || []).join("\n"),
    kind,
    values: kind === "network" ? rule.network : kind === "any" ? "" : rule[kind].join("\n"),
    destination: rule.outboundTag === WORK_TAG ? "work" : rule.outboundTag === "direct" ? "direct" : "foreign",
  };
}

function rowToRule(row, index, multiple) {
  const rule = { type: "field" };
  const inbound = lines(row.inbound);
  if (inbound.length) rule.inboundTag = inbound;
  if (row.kind === "any") {
    if (!inbound.length) throw new Error(`Правило ${index + 1}: для условия «Любой» нужен вход.`);
  } else if (row.kind === "network") {
    const network = row.values.trim().replace(/\s/g, "");
    if (!["tcp", "udp", "tcp,udp", "udp,tcp"].includes(network)) throw new Error(`Правило ${index + 1}: сеть должна быть tcp, udp или tcp,udp.`);
    rule.network = network;
  } else if (["domain", "ip"].includes(row.kind)) {
    const values = lines(row.values);
    if (!values.length) throw new Error(`Правило ${index + 1}: добавьте хотя бы одно значение.`);
    rule[row.kind] = values;
  } else {
    throw new Error(`Правило ${index + 1}: неизвестный тип условия.`);
  }
  if (row.destination === "work") rule.outboundTag = WORK_TAG;
  else if (row.destination === "direct") rule.outboundTag = "direct";
  else if (row.destination === "foreign") {
    if (multiple) rule.balancerTag = BALANCER_TAG;
    else rule.outboundTag = FOREIGN_TAG;
  } else throw new Error(`Правило ${index + 1}: неизвестное направление.`);
  return rule;
}

function lines(value) { return value.split(/\r?\n/).map(x => x.trim()).filter(Boolean); }

function parseRoutesText(text) {
  let input;
  try { input = JSON.parse(text); }
  catch { throw new Error("Не удалось прочитать JSON правил."); }
  const rules = Array.isArray(input) ? input : input?.routing?.rules;
  if (!Array.isArray(rules)) throw new Error("Нужен массив правил или конфиг с routing.rules.");
  return rules.map((rule, index) => {
    const number = index + 1;
    if (!rule || typeof rule !== "object" || Array.isArray(rule)) throw new Error(`Правило ${number}: нужен JSON-объект.`);
    const allowed = new Set(["type", "inboundTag", "domain", "ip", "network", "outboundTag", "balancerTag"]);
    const extra = Object.keys(rule).filter(key => !allowed.has(key));
    if (extra.length) throw new Error(`Правило ${number}: таблица не поддерживает ${extra.join(", ")}.`);
    if (rule.type !== undefined && rule.type !== "field") throw new Error(`Правило ${number}: поддерживается только type=field.`);
    if (rule.inboundTag !== undefined && (!Array.isArray(rule.inboundTag) || !rule.inboundTag.length || rule.inboundTag.some(value => typeof value !== "string" || !value.trim()))) throw new Error(`Правило ${number}: inboundTag должен быть непустым массивом строк.`);
    const kinds = ["domain", "ip", "network"].filter(key => key in rule);
    if (kinds.length > 1) throw new Error(`Правило ${number}: укажите один тип условия.`);
    if (!kinds.length && !rule.inboundTag) throw new Error(`Правило ${number}: добавьте условие или inboundTag.`);
    if (kinds[0] === "network" && (typeof rule.network !== "string" || !["tcp", "udp", "tcp,udp", "udp,tcp"].includes(rule.network.replace(/\s/g, "")))) throw new Error(`Правило ${number}: неверный network.`);
    if (["domain", "ip"].includes(kinds[0]) && (!Array.isArray(rule[kinds[0]]) || !rule[kinds[0]].length || rule[kinds[0]].some(value => typeof value !== "string" || !value.trim()))) throw new Error(`Правило ${number}: ${kinds[0]} должен быть непустым массивом строк.`);
    if (("outboundTag" in rule) === ("balancerTag" in rule)) throw new Error(`Правило ${number}: нужно ровно одно направление.`);
    if ("outboundTag" in rule && ![WORK_TAG, FOREIGN_TAG, "direct"].includes(rule.outboundTag)) throw new Error(`Правило ${number}: неизвестный outboundTag ${rule.outboundTag}.`);
    if ("balancerTag" in rule && rule.balancerTag !== BALANCER_TAG) throw new Error(`Правило ${number}: неизвестный balancerTag ${rule.balancerTag}.`);
    return ruleToRow(rule);
  });
}

function parseVless(raw, tag) {
  const link = raw.trim().replace(/^vless\\:\/\//, "vless://");
  const connection = link.split("#", 1)[0];
  if (!connection.startsWith("vless://") || /\s|%(?![0-9a-f]{2})/i.test(connection)) throw new Error("Нужна ссылка vless:// без пробелов и с корректным %XX-кодированием.");
  let url;
  try { url = new URL(link); } catch { throw new Error("Проверьте UUID, адрес и порт в VLESS-ссылке."); }
  if (url.protocol !== "vless:" || !url.hostname || !url.port || url.password || (url.pathname && url.pathname !== "/")) throw new Error("Проверьте UUID, адрес и порт в VLESS-ссылке.");
  let uuid;
  try { uuid = decodeURIComponent(url.username); } catch { throw new Error("UUID содержит неверное кодирование."); }
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(uuid)) throw new Error("В VLESS-ссылке нужен корректный UUID.");
  const params = new Map();
  for (const [key, value] of url.searchParams) {
    if (params.has(key)) throw new Error(`Повторяется параметр ${key}.`);
    params.set(key, value);
  }
  const take = (key, fallback = "") => { const value = params.get(key) ?? fallback; params.delete(key); return value; };
  const bool = (key, fallback = "false") => {
    const value = take(key, fallback).toLowerCase();
    if (!["true", "false", "1", "0"].includes(value)) throw new Error(`${key} должен быть true/false или 1/0.`);
    return value === "true" || value === "1";
  };
  let network = take("type", "tcp");
  network = { raw: "tcp", websocket: "ws", splithttp: "xhttp" }[network] || network;
  if (!["tcp", "ws", "grpc", "xhttp", "httpupgrade"].includes(network)) throw new Error("Поддерживаются TCP, WS, gRPC, XHTTP и HTTPUpgrade.");
  const security = take("security", "none");
  if (!["none", "tls", "reality"].includes(security)) throw new Error("Поддерживаются security=none, tls и reality.");
  const encryption = take("encryption", "none");
  if (!encryption) throw new Error("Параметр encryption пуст.");
  const flow = take("flow");
  if (!["", "xtls-rprx-vision", "xtls-rprx-vision-udp443"].includes(flow)) throw new Error("Неизвестный flow.");
  if (flow && (network !== "tcp" || security === "none")) throw new Error("XTLS Vision поддерживается только с TCP + TLS/Reality.");
  if (!["", "none"].includes(take("headerType", "none"))) throw new Error("headerType кроме none не поддерживается.");

  const host = url.hostname.replace(/^\[|\]$/g, "");
  const stream = { network, security };
  if (security === "tls") {
    const tls = { serverName: take("sni", host), fingerprint: take("fp", "chrome") };
    if (params.has("insecure") && params.has("allowInsecure")) throw new Error("Оставьте один параметр: insecure или allowInsecure.");
    tls.allowInsecure = bool(params.has("insecure") ? "insecure" : "allowInsecure");
    const alpn = take("alpn");
    if (alpn) { tls.alpn = alpn.split(","); if (tls.alpn.some(x => !x)) throw new Error("Пустое значение в alpn."); }
    stream.tlsSettings = tls;
  } else if (security === "reality") {
    if (!["tcp", "grpc", "xhttp"].includes(network)) throw new Error("Reality поддерживается с TCP, gRPC или XHTTP.");
    const publicKey = take("pbk");
    if (!/^[A-Za-z0-9_-]{43}$/.test(publicKey)) throw new Error("Для Reality нужен 43-символьный pbk.");
    try { if (atob(publicKey.replace(/-/g, "+").replace(/_/g, "/") + "=").length !== 32) throw new Error(); }
    catch { throw new Error("Некорректный публичный ключ Reality."); }
    const shortId = take("sid");
    if (!/^(?:[0-9a-f]{2}){0,8}$/i.test(shortId)) throw new Error("sid должен содержать чётное число hex-символов, до 16.");
    const sni = take("sni");
    if (!sni) throw new Error("Для Reality укажите sni.");
    stream.realitySettings = { serverName: sni, fingerprint: take("fp", "chrome"), publicKey, shortId, spiderX: take("spx", "/") };
  }
  if (stream.tlsSettings?.fingerprint === "" || stream.realitySettings?.fingerprint === "") throw new Error("fp не должен быть пустым.");

  if (["ws", "httpupgrade", "xhttp"].includes(network)) {
    const transport = { path: take("path", "/") || "/" };
    const transportHost = take("host");
    if (transportHost) {
      if (network === "ws") transport.headers = { Host: transportHost };
      else transport.host = transportHost;
    }
    if (network === "xhttp") {
      const mode = take("mode", "auto");
      if (!["auto", "packet-up", "stream-up", "stream-one"].includes(mode)) throw new Error("Неизвестный режим XHTTP.");
      transport.mode = mode;
      const extra = take("extra");
      if (extra) { try { transport.extra = JSON.parse(extra); if (!transport.extra || Array.isArray(transport.extra) || typeof transport.extra !== "object") throw new Error(); } catch { throw new Error("XHTTP extra должен быть JSON-объектом."); } }
    }
    stream[{ ws: "wsSettings", httpupgrade: "httpupgradeSettings", xhttp: "xhttpSettings" }[network]] = transport;
  } else if (network === "grpc") {
    const mode = take("mode", "gun");
    if (!["gun", "multi"].includes(mode)) throw new Error("Поддерживаются режимы gRPC gun и multi.");
    stream.grpcSettings = { serviceName: take("serviceName"), authority: take("authority"), multiMode: mode === "multi" };
  }
  if ([...params.values()].some(Boolean)) throw new Error(`Неподдерживаемые параметры: ${[...params.keys()].join(", ")}.`);
  return { tag, protocol: "vless", settings: { vnext: [{ address: host, port: Number(url.port), users: [{ id: uuid.toLowerCase(), encryption, flow }] }] }, streamSettings: stream };
}

function buildConfig() {
  if (!state.workKey.trim() || state.foreign.some(item => !item.key.trim()) || !state.foreign.length) return null;
  const multiple = state.foreign.length > 1;
  const work = parseVless(state.workKey, WORK_TAG);
  const foreign = state.foreign.map((item, index) => parseVless(item.key, multiple ? `${FOREIGN_PREFIX}${index + 1}` : FOREIGN_TAG));
  const config = clone(template);
  config.remarks = state.title.trim() || (multiple ? "Lex — VLESS-Работа + зарубежные серверы (автовыбор)" : "Lex — VLESS-Работа + VLESS-Заграница");
  if (state.description.trim()) {
    config.meta = { ...config.meta, serverDescription: state.description.trim() };
  } else if (config.meta) {
    delete config.meta.serverDescription;
  }
  config.outbounds = [ ...foreign, work, ...config.outbounds.filter(outbound => ![WORK_TAG, FOREIGN_TAG].includes(outbound.tag)) ];
  config.routing.rules = state.rules.map((row, index) => rowToRule(row, index, multiple));
  if (multiple) {
    config.routing.balancers = [{ tag: BALANCER_TAG, selector: [FOREIGN_PREFIX], fallbackTag: foreign[0].tag, strategy: { type: "leastPing" } }];
    config.observatory = { subjectSelector: [FOREIGN_PREFIX], probeUrl: "https://www.google.com/generate_204", probeInterval: "30s", enableConcurrency: true };
  }
  return config;
}

function element(tag, attrs = {}, text = "") {
  const node = document.createElement(tag);
  Object.entries(attrs).forEach(([name, value]) => node.setAttribute(name, value));
  node.textContent = text;
  return node;
}

function renderForeign() {
  const list = $("#foreign-list");
  list.replaceChildren();
  state.foreign.forEach((item, index) => {
    const entry = element("div", { class: "foreign-entry" });
    const head = element("div", { class: "foreign-entry-head" });
    head.append(element("span", {}, `Сервер ${index + 1}`));
    if (state.foreign.length > 1) {
      const remove = element("button", { type: "button", class: "text-action", "aria-label": `Удалить сервер ${index + 1}` }, "Удалить");
      remove.addEventListener("click", () => { state.foreign.splice(index, 1); renderForeign(); refresh(); });
      head.append(remove);
    }
    entry.append(head);
    const keyId = `foreign-key-${index}`, noteId = `foreign-note-${index}`;
    entry.append(element("label", { for: keyId }, "VLESS-ключ"));
    const wrap = element("div", { class: "input-wrap" });
    const key = element("input", { id: keyId, type: "password", spellcheck: "false", autocomplete: "off", placeholder: "vless://uuid@server:port?..." });
    key.value = item.key;
    key.addEventListener("input", () => { item.key = key.value; refresh(); });
    const reveal = element("button", { type: "button", class: "reveal", "aria-label": "Показать ключ" }, "Показать");
    reveal.addEventListener("click", () => toggleReveal(key, reveal));
    wrap.append(key, reveal);
    entry.append(wrap);
    const noteLabel = element("label", { for: noteId }, "Примечание ");
    noteLabel.append(element("span", { class: "optional" }, "необязательно"));
    const note = element("input", { id: noteId, type: "text", autocomplete: "off", placeholder: "Например, Нидерланды" });
    note.value = item.note;
    note.addEventListener("input", () => { item.note = note.value; persistState(); });
    entry.append(noteLabel, note);
    list.append(entry);
  });
}

function toggleReveal(input, button) {
  input.type = input.type === "password" ? "text" : "password";
  button.textContent = input.type === "password" ? "Показать" : "Скрыть";
  button.setAttribute("aria-label", button.textContent + " ключ");
}

function select(options, value, onChange) {
  const node = element("select");
  options.forEach(([key, label]) => node.append(element("option", { value: key }, label)));
  node.value = value;
  node.addEventListener("change", () => onChange(node.value));
  return node;
}

function renderRoutes() {
  const body = $("#routes");
  body.replaceChildren();
  state.rules.forEach((row, index) => {
    const tr = element("tr", { draggable: "true" });
    const orderTd = element("td");
    const order = element("div", { class: "order" });
    order.append(element("span", { class: "handle", title: "Перетащить строку", "aria-hidden": "true" }, "⠿"), element("strong", {}, String(index + 1).padStart(2, "0")));
    orderTd.append(order);
    const inboundTd = element("td");
    const inbound = element("input", { type: "text", placeholder: "Все", "aria-label": `Вход правила ${index + 1}` });
    inbound.value = row.inbound;
    inbound.addEventListener("input", () => { row.inbound = inbound.value; refresh(); });
    inboundTd.append(inbound);
    const kindTd = element("td");
    kindTd.append(select([["domain", "Домен"], ["ip", "IP / сеть"], ["network", "Протокол"], ["any", "Любой"]], row.kind, value => { row.kind = value; refresh(); }));
    const valuesTd = element("td");
    const values = element("textarea", { placeholder: row.kind === "network" ? "tcp,udp" : "По одному в строке", "aria-label": `Значения правила ${index + 1}` });
    values.value = row.values;
    values.disabled = row.kind === "any";
    values.addEventListener("input", () => { row.values = values.value; refresh(); });
    valuesTd.append(values);
    const destinationTd = element("td");
    destinationTd.append(select([["work", "Работа"], ["foreign", "Заграница"], ["direct", "Напрямую"]], row.destination, value => { row.destination = value; refresh(); }));
    const deleteTd = element("td");
    const remove = element("button", { type: "button", class: "remove-route", "aria-label": `Удалить правило ${index + 1}` }, "×");
    remove.addEventListener("click", () => { state.rules.splice(index, 1); renderRoutes(); refresh(); });
    deleteTd.append(remove);
    tr.append(orderTd, inboundTd, kindTd, valuesTd, destinationTd, deleteTd);
    tr.addEventListener("dragstart", event => {
      draggedIndex = index;
      event.dataTransfer.effectAllowed = "move";
      event.dataTransfer.setData("text/plain", String(index));
      tr.classList.add("dragging");
    });
    tr.addEventListener("dragover", event => { event.preventDefault(); tr.classList.add("drag-over"); });
    tr.addEventListener("dragleave", () => tr.classList.remove("drag-over"));
    tr.addEventListener("drop", event => {
      event.preventDefault();
      if (draggedIndex === null || draggedIndex === index) return;
      const [moved] = state.rules.splice(draggedIndex, 1);
      state.rules.splice(index, 0, moved);
      draggedIndex = null;
      renderRoutes(); refresh();
    });
    tr.addEventListener("dragend", () => { draggedIndex = null; tr.classList.remove("dragging", "drag-over"); });
    body.append(tr);
  });
}

function persistState() {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
    $("#save-status").textContent = "Сохранено в браузере";
  } catch {
    $("#save-status").textContent = "Не удалось сохранить в браузере";
  }
}

function routeFeedback(message) {
  const feedback = $("#routes-feedback");
  feedback.textContent = message;
  feedback.hidden = !message;
}

function refresh(save = true) {
  if (save) persistState();
  const error = $("#error"), output = $("#output"), copy = $("#copy"), status = $("#config-state");
  error.hidden = true;
  latestJson = "";
  copy.disabled = true;
  try {
    const config = buildConfig();
    if (!config) {
      output.textContent = "Добавьте рабочий и хотя бы один зарубежный VLESS-ключ, чтобы увидеть конфиг.";
      status.textContent = "Ожидает ключи";
      return;
    }
    latestJson = JSON.stringify(config, null, 2) + "\n";
    output.textContent = latestJson;
    status.textContent = "Готов к копированию";
    copy.disabled = false;
  } catch (exc) {
    error.textContent = exc.message;
    error.hidden = false;
    output.textContent = "Исправьте данные выше, чтобы получить конфиг.";
    status.textContent = "Нужна проверка";
  }
}

function loadSaved() {
  try {
    const saved = JSON.parse(localStorage.getItem(STORAGE_KEY));
    if (!saved || typeof saved !== "object") return false;
    if (typeof saved.workKey !== "string" || typeof saved.workNote !== "string" || !Array.isArray(saved.foreign) || !saved.foreign.length || !Array.isArray(saved.rules)) return false;
    if (saved.foreign.some(x => !x || typeof x.key !== "string" || typeof x.note !== "string")) return false;
    if (saved.rules.some(x => !x || ["inbound", "kind", "values", "destination"].some(k => typeof x[k] !== "string"))) return false;
    if (saved.description !== undefined && typeof saved.description !== "string") return false;
    if (saved.title !== undefined && typeof saved.title !== "string") return false;
    state = { ...saved, title: saved.title || DEFAULT_TITLE, description: saved.description || DEFAULT_DESCRIPTION };
    return true;
  } catch { return false; }
}

async function init() {
  try {
    const response = await fetch("../tools/happ-two-vless.json");
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    template = await response.json();
  } catch {
    $("#error").textContent = "Не удалось загрузить шаблон. Запустите страницу через локальный сервер из корня проекта: python3 -m http.server 8000";
    $("#error").hidden = false;
    return;
  }
  state = defaultState();
  const restored = loadSaved();
  $("#work-key").value = state.workKey;
  $("#work-note").value = state.workNote;
  $("#config-title").value = state.title;
  $("#config-title").addEventListener("input", event => { state.title = event.target.value; refresh(); });
  $("#config-description").value = state.description;
  $("#config-description").addEventListener("input", event => { state.description = event.target.value; refresh(); });
  $("#work-key").addEventListener("input", event => { state.workKey = event.target.value; refresh(); });
  $("#work-note").addEventListener("input", event => { state.workNote = event.target.value; persistState(); });
  document.querySelectorAll("[data-reveal]").forEach(button => button.addEventListener("click", () => toggleReveal(document.getElementById(button.dataset.reveal), button)));
  $("#add-foreign").addEventListener("click", () => { state.foreign.push({ key: "", note: "" }); renderForeign(); refresh(); document.getElementById(`foreign-key-${state.foreign.length - 1}`).focus(); });
  $("#add-route").addEventListener("click", () => { state.rules.push({ inbound: "", kind: "domain", values: "", destination: "foreign" }); renderRoutes(); refresh(); });
  $("#copy-routes").addEventListener("click", async () => {
    try {
      const text = JSON.stringify(state.rules.map((row, index) => rowToRule(row, index, state.foreign.length > 1)), null, 2);
      await navigator.clipboard.writeText(text);
      routeFeedback("Правила скопированы в формате JSON.");
    } catch (exc) {
      routeFeedback(exc.message || "Не удалось скопировать правила.");
    }
  });
  $("#paste-routes").addEventListener("click", async () => {
    $("#routes-import").hidden = false;
    $("#routes-import-error").hidden = true;
    routeFeedback("");
    $("#routes-json").value = "";
    $("#routes-json").focus();
    try { $("#routes-json").value = await navigator.clipboard.readText(); }
    catch { /* Ручная вставка остаётся доступной. */ }
  });
  $("#cancel-routes").addEventListener("click", () => { $("#routes-import").hidden = true; $("#routes-import-error").hidden = true; });
  $("#apply-routes").addEventListener("click", () => {
    try {
      const imported = parseRoutesText($("#routes-json").value);
      state.rules = imported;
      renderRoutes(); refresh();
      $("#routes-import").hidden = true;
      $("#routes-import-error").hidden = true;
      routeFeedback(`Импортировано правил: ${imported.length}.`);
    } catch (exc) {
      $("#routes-import-error").textContent = exc.message;
      $("#routes-import-error").hidden = false;
    }
  });
  $("#reset").addEventListener("click", () => {
    try { localStorage.removeItem(STORAGE_KEY); }
    catch { $("#save-status").textContent = "Не удалось очистить данные браузера"; return; }
    state = defaultState();
    $("#work-key").value = "";
    $("#work-note").value = "";
    $("#config-title").value = state.title;
    $("#config-description").value = state.description;
    renderForeign(); renderRoutes(); refresh(false);
    $("#routes-import").hidden = true;
    routeFeedback("");
    $("#save-status").textContent = "Сохранённые данные удалены";
  });
  $("#copy").addEventListener("click", async () => {
    if (!latestJson) return;
    try { await navigator.clipboard.writeText(latestJson); $("#copy").textContent = "Скопировано ✓"; setTimeout(() => $("#copy").textContent = "Скопировать JSON", 1800); }
    catch { $("#error").textContent = "Копирование недоступно. Выделите JSON и скопируйте вручную."; $("#error").hidden = false; }
  });
  renderForeign(); renderRoutes(); refresh(false);
  $("#save-status").textContent = restored ? "Загружено из браузера" : "Автосохранение включено";
}

init();
