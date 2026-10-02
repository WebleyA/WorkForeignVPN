#!/usr/bin/env python3
"""Serve a local dashboard and probe fixed destinations. Standard library only."""

import argparse
import http.client
import json
from pathlib import Path
import socket
import ssl
import struct
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

PAGE = Path(__file__).resolve().parent / "index.html"
TARGETS = {
    "yandex": ("yandex.ru", 443, "https"),
    "ru_ip": ("77.88.55.88", 80, "http_ip"),
    "google": ("google.com", 443, "https"),
    "foreign_ip": ("142.251.13.113", 443, "https_ip"),
    "openai": ("api.openai.com", 443, "https"),
    "claude": ("api.anthropic.com", 443, "https"),
    "big3": ("lk.big3.ru", 443, "https"),
    "postgres": ("10.10.13.98", 5432, "postgres"),
}
TIMEOUT = 6
POSTGRES_TIMEOUT = 2
DIRECT_HOSTS = {"ru_ip": "yandex.ru", "foreign_ip": "google.com"}


def probe(target):
    host, port, protocol = TARGETS[target]
    timeout = POSTGRES_TIMEOUT if protocol == "postgres" else TIMEOUT
    start = time.monotonic()
    result = {"target": target, "status": "error", "reachable": False}
    try:
        if protocol == "postgres":
            with socket.create_connection((host, port), timeout=timeout) as connection:
                result["peer"] = connection.getpeername()[0]
                result["reachable"] = True
                connection.settimeout(max(0.001, timeout - (time.monotonic() - start)))
                connection.sendall(struct.pack("!II", 8, 80877103))
                connection.settimeout(max(0.001, timeout - (time.monotonic() - start)))
                response = connection.recv(1)
                if response in (b"S", b"N"):
                    result.update(status="ok", message="PostgreSQL отвечает",
                                  detail="TCP открыт · протокол PostgreSQL подтверждён · "
                                  + ("SSL поддерживается" if response == b"S" else "SSL не поддерживается"))
                else:
                    result.update(status="warning", message="Порт открыт, PostgreSQL не подтверждён",
                                  detail="Сервер закрыл соединение" if not response else "Неожиданный ответ на SSLRequest")
        else:
            direct_ip = protocol in ("http_ip", "https_ip")
            http_host = DIRECT_HOSTS[target] if direct_ip else host
            tls_context = ssl.create_default_context() if protocol != "http_ip" else None
            connection = (http.client.HTTPConnection(http_host, port, timeout=TIMEOUT) if protocol == "http_ip"
                          else http.client.HTTPSConnection(http_host, port, timeout=TIMEOUT, context=tls_context))
            try:
                if direct_ip:
                    # Connect to a numeric IPv4 address without getaddrinfo or
                    # a system DNS lookup, then reuse the socket for HTTP.
                    connection.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    connection.sock.settimeout(TIMEOUT)
                    connection.sock.connect((host, port))
                    if protocol == "https_ip":
                        connection.sock = tls_context.wrap_socket(connection.sock, server_hostname=http_host)
                else:
                    connection.connect()
                result["peer"] = connection.sock.getpeername()[0]
                result["reachable"] = True
                is_api = target in ("openai", "claude")
                headers = {"User-Agent": "LocalConnectivityCheck/1.0"}
                if direct_ip:
                    headers["Host"] = http_host
                if target == "claude":
                    headers["anthropic-version"] = "2023-06-01"
                connection.request("GET" if is_api else "HEAD", "/v1/models" if is_api else "/",
                                   headers=headers)
                response = connection.getresponse()
                code = response.status
                result.update(status="ok" if 200 <= code < 400 else "warning",
                              message="Сайт доступен" if 200 <= code < 400 else "Сайт отвечает с ошибкой HTTP",
                              detail=f"{'HTTPS' if tls_context else 'HTTP'}{' по IP · без DNS' if direct_ip else ''} · HTTP {code} {response.reason}", http_status=code)
                if code == 403:
                    result.update(status="error", message="Доступ запрещён · HTTP 403")
                if is_api and code == 401:
                    result.update(status="ok", message="API доступен · требуется авторизация",
                                  detail=f"HTTPS · HTTP {code} {response.reason} · проверка без API-ключа")
            finally:
                connection.close()
    except socket.gaierror:
        result.update(message="Не удалось разрешить адрес", detail="Проверь DNS и подключение к сети")
    except ssl.SSLCertVerificationError:
        result.update(message="Ошибка сертификата TLS", detail="Не удалось подтвердить сертификат сервера")
    except ssl.SSLError:
        result.update(message="Не удалось установить TLS", detail="Сбой защищённого соединения")
    except (TimeoutError, socket.timeout):
        result.update(message="Сервер не ответил вовремя", detail=f"Таймаут проверки: {timeout} с")
    except ConnectionRefusedError:
        result.update(message="Соединение отклонено", detail="Адрес доступен, но порт не принимает соединение")
    except (OSError, http.client.HTTPException) as error:
        result.update(message="Ошибка соединения", detail=str(error))
    result["elapsed_ms"] = round((time.monotonic() - start) * 1000)
    return result


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def send_content(self, status, content, content_type):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        origin = self.headers.get("Origin")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.end_headers()
        self.wfile.write(content)

    def do_GET(self):
        host_header = self.headers.get("Host", "")
        try:
            host_url = urlsplit("//" + host_header)
            valid_host = (host_url.hostname in getattr(self.server, "allowed_hosts", {"127.0.0.1", "localhost"})
                          and not host_url.username and not host_url.password
                          and not host_url.path and not host_url.query and not host_url.fragment)
            host_url.port  # Validate an optional port.
        except ValueError:
            valid_host = False
        origins = {None, "null", f"http://{host_header}", f"https://{host_header}"}
        if not valid_host or self.headers.get("Origin") not in origins:
            self.send_error(403)
            return
        url = urlsplit(self.path)
        if url.path in ("/", "/connectivity.html"):
            self.send_content(200, PAGE.read_bytes(), "text/html; charset=utf-8")
        elif url.path == "/api/check":
            values = parse_qs(url.query).get("target", [])
            if len(values) != 1 or values[0] not in TARGETS:
                self.send_content(400, b'{"error":"Unknown target"}', "application/json")
                return
            content = json.dumps(probe(values[0]), ensure_ascii=False).encode("utf-8")
            self.send_content(200, content, "application/json; charset=utf-8")
        else:
            self.send_error(404)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--host", default="127.0.0.1", help="Адрес прослушивания; 0.0.0.0 для доступа из сети")
    parser.add_argument("--allow-host", action="append", default=[], metavar="DOMAIN_OR_IP",
                        help="Разрешённый домен или IP в ссылке на страницу, без схемы и порта; можно повторить")
    args = parser.parse_args()
    try:
        with ThreadingHTTPServer((args.host, args.port), Handler) as server:
            server.allowed_hosts = {"127.0.0.1", "localhost", *args.allow_host}
            if args.host != "0.0.0.0":
                server.allowed_hosts.add(args.host)
            print(f"Открой http://127.0.0.1:{server.server_port}/ · Для остановки нажми Ctrl+C", flush=True)
            if args.host != "127.0.0.1":
                print(f"Доступ из сети включён на {args.host}:{server.server_port}; разрешённые адреса: "
                      + ", ".join(sorted(server.allowed_hosts)), flush=True)
            server.serve_forever()
    except KeyboardInterrupt:
        pass
    except OSError as error:
        parser.exit(1, f"Не удалось запустить локальный сервер: {error}\n")


if __name__ == "__main__":
    main()
