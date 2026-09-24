#!/usr/bin/env python3
"""Build the two-outbound Happ profile locally using two VLESS share links."""

import argparse
import base64
import copy
import getpass
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import parse_qsl, unquote, urlsplit
from uuid import UUID


ROOT = Path(__file__).resolve().parent
WORK_TAG = "VLESS-Работа"
DEFAULT_TAG = "VLESS-Заграница"


def parse_vless(link, tag):
    """Convert a supported share link; never silently discard active options."""
    link = link.strip().replace("vless\\://", "vless://", 1)
    # The display name after # is not a connection parameter; exports may leave spaces there.
    connection_part = link.split("#", 1)[0]
    if not link.startswith("vless://") or re.search(r"\s|%(?![0-9a-fA-F]{2})", connection_part):
        raise ValueError("Нужна одна ссылка vless:// без пробелов; специальные символы кодируются как %XX.")
    try:
        uri = urlsplit(link)
        host, port = uri.hostname, uri.port
        if not host or not port or uri.password is not None or uri.path not in ("", "/"):
            raise ValueError
        user_id = str(UUID(unquote(uri.username or "")))
        pairs = parse_qsl(uri.query, keep_blank_values=True, strict_parsing=True)
    except (ValueError, UnicodeError):
        raise ValueError("Проверьте UUID, адрес, порт и параметры ссылки VLESS.") from None
    params = {}
    for key, value in pairs:
        if key in params:
            raise ValueError("В ссылке повторяются параметры; оставьте одно значение каждого параметра.")
        params[key] = value

    def take(name, default=""):
        return params.pop(name, default)

    def boolean(name, default="false"):
        value = take(name, default).lower()
        if value not in ("true", "false", "1", "0"):
            raise ValueError(f"Параметр {name} должен быть true/false или 1/0.")
        return value in ("true", "1")

    network = take("type", "tcp")
    network = {"raw": "tcp", "websocket": "ws", "splithttp": "xhttp"}.get(network, network)
    if network not in ("tcp", "ws", "grpc", "xhttp", "httpupgrade"):
        raise ValueError("Поддерживаются транспорты TCP, WS, gRPC, XHTTP и HTTPUpgrade.")
    security = take("security", "none")
    if security not in ("none", "tls", "reality"):
        raise ValueError("Поддерживаются security=none, tls и reality.")
    encryption = take("encryption", "none")
    if not encryption:
        raise ValueError("Параметр encryption не должен быть пустым.")
    flow = take("flow")
    if flow not in ("", "xtls-rprx-vision", "xtls-rprx-vision-udp443"):
        raise ValueError("Неизвестный flow; поддерживается пустой flow или XTLS Vision.")
    if flow and (network != "tcp" or security not in ("tls", "reality")):
        raise ValueError("В этом скрипте XTLS Vision поддерживается только с TCP + TLS/Reality.")
    if take("headerType", "none") not in ("", "none"):
        raise ValueError("Маскировка headerType кроме none пока не поддерживается.")

    stream = {"network": network, "security": security}
    if security == "tls":
        tls = {"serverName": take("sni", host), "fingerprint": take("fp", "chrome")}
        if "allowInsecure" in params and "insecure" in params:
            raise ValueError("Оставьте только один параметр: insecure или allowInsecure.")
        tls["allowInsecure"] = boolean("insecure" if "insecure" in params else "allowInsecure")
        alpn = take("alpn")
        if alpn:
            tls["alpn"] = alpn.split(",")
            if any(not item for item in tls["alpn"]):
                raise ValueError("В alpn есть пустое значение.")
        stream["tlsSettings"] = tls
    elif security == "reality":
        if network not in ("tcp", "grpc", "xhttp"):
            raise ValueError("Reality поддерживается только с TCP, gRPC или XHTTP.")
        public_key = take("pbk")
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", public_key):
            raise ValueError("Для Reality нужен pbk: публичный ключ X25519 в Base64URL (43 символа).")
        if len(base64.urlsafe_b64decode(public_key + "=")) != 32:
            raise ValueError("Неверная длина публичного ключа Reality.")
        short_id = take("sid")
        if not re.fullmatch(r"(?:[0-9a-fA-F]{2}){0,8}", short_id):
            raise ValueError("sid должен содержать от 0 до 16 hex-символов, чётное количество.")
        sni = take("sni")
        if not sni:
            raise ValueError("Для Reality укажите sni в ссылке.")
        stream["realitySettings"] = {
            "serverName": sni, "fingerprint": take("fp", "chrome"),
            "publicKey": public_key, "shortId": short_id, "spiderX": take("spx", "/")
        }

    if network in ("ws", "httpupgrade", "xhttp"):
        transport = {"path": take("path", "/") or "/"}
        transport_host = take("host")
        if transport_host:
            if network == "ws":
                transport["headers"] = {"Host": transport_host}
            else:
                transport["host"] = transport_host
        if network == "xhttp":
            mode = take("mode", "auto")
            if mode not in ("auto", "packet-up", "stream-up", "stream-one"):
                raise ValueError("Неизвестный режим XHTTP.")
            transport["mode"] = mode
            extra = take("extra")
            if extra:
                try:
                    parsed_extra = json.loads(extra)
                    if not isinstance(parsed_extra, dict):
                        raise ValueError
                    json.dumps(parsed_extra, allow_nan=False)
                except (ValueError, TypeError):
                    raise ValueError("XHTTP extra должен быть JSON-объектом.") from None
                transport["extra"] = parsed_extra
        stream[{"ws": "wsSettings", "httpupgrade": "httpupgradeSettings", "xhttp": "xhttpSettings"}[network]] = transport
    elif network == "grpc":
        mode = take("mode", "gun")
        if mode not in ("gun", "multi"):
            raise ValueError("Поддерживаются режимы gRPC gun и multi.")
        stream["grpcSettings"] = {
            "serviceName": take("serviceName"), "authority": take("authority"),
            "multiMode": mode == "multi"
        }

    # Empty optional fields commonly appear in exported links and have no effect.
    if any(params.values()):
        raise ValueError("Ссылка содержит неподдерживаемые параметры. Конфиг не создан, чтобы не потерять настройки.")
    for settings_name in ("tlsSettings", "realitySettings"):
        if settings_name in stream and not stream[settings_name]["fingerprint"]:
            raise ValueError("fp не должен быть пустым.")
    user = {"id": user_id, "encryption": encryption, "flow": flow}
    return {
        "tag": tag, "protocol": "vless",
        "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]},
        "streamSettings": stream
    }


def build_config(template, first, second):
    config = copy.deepcopy(template)
    replacements = {WORK_TAG: first, DEFAULT_TAG: second}
    outbounds = config.get("outbounds", [])
    for tag in replacements:
        if sum(item.get("tag") == tag for item in outbounds) != 1:
            raise ValueError("В шаблоне должны быть два уникальных выхода VLESS-Работа и VLESS-Заграница.")
    config["outbounds"] = [replacements.get(item.get("tag"), item) for item in outbounds]
    config["remarks"] = "Lex — VLESS-Работа + VLESS-Заграница"
    return config


def ask_vless(prompt, tag):
    while True:
        link = getpass.getpass(prompt) if sys.stdin.isatty() else input(prompt)
        try:
            return parse_vless(link, tag)
        except ValueError as exc:
            print(f"Ошибка: {exc} Вставьте ссылку ещё раз.", file=sys.stderr)


def save_config(config, output=None):
    payload = json.dumps(config, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    index = 0
    while True:
        suffix = f".{index}" if index else ""
        path = Path(output) if output is not None else ROOT / f"happ-two-vless.generated{suffix}.json"
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            break
        except FileExistsError:
            if output is not None:
                raise ValueError("Выходной файл уже существует. Выберите другое имя через --output.") from None
            index += 1
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
    except BaseException:
        path.unlink()
        raise
    return path.resolve()


def load_template():
    path = ROOT / "happ-two-vless.local.json"
    if not path.exists():
        path = ROOT / "happ-two-vless.json"
    return json.loads(path.read_text(encoding="utf-8"))


def main():
    parser = argparse.ArgumentParser(description="Создать конфиг Happ из двух VLESS-ссылок.")
    parser.add_argument("--output", type=Path, help="Отдельный файл результата (существующий файл не перезаписывается).")
    args = parser.parse_args()
    try:
        template = load_template()
        print("VLESS-Работа: рабочие сети и big3.ru. VLESS-Заграница: остальной VPN-трафик.")
        if sys.stdin.isatty():
            print("Вставляемые ключи скрыты. После каждой ссылки нажмите Enter.")
        first = ask_vless("VLESS-Работа (vless://): ", WORK_TAG)
        second = ask_vless("VLESS-Заграница (vless://): ", DEFAULT_TAG)
        result = save_config(build_config(template, first, second), args.output)
    except (EOFError, KeyboardInterrupt):
        print("\nВвод отменён. Итоговый конфиг не создан.", file=sys.stderr)
        return 1
    except (OSError, ValueError) as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        return 1
    print(f"\nКонфиг сохранён: {result}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
