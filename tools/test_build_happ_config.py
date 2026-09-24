import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlencode

import build_happ_config as app


UUID_1 = "11111111-1111-4111-8111-111111111111"
UUID_2 = "22222222-2222-4222-8222-222222222222"
PUBLIC_KEY = "qGPTy8EZokn3hWp6hKBQ0MVvEuLRJCcv5UdWeP4TVhI"


def link(host="one.example.invalid", user=UUID_1, **params):
    return f"vless://{user}@{host}:443?{urlencode(params or {'security': 'tls'})}#Test"


class ParserTests(unittest.TestCase):
    def test_reality_vision(self):
        uri = link(security="reality", type="tcp", encryption="none",
                   flow="xtls-rprx-vision", pbk=PUBLIC_KEY, sid="ab12",
                   sni="cover.example.invalid", fp="firefox", spx="/a?b=c")
        result = app.parse_vless(uri, app.WORK_TAG)
        self.assertEqual(result["tag"], app.WORK_TAG)
        self.assertEqual(result["settings"]["vnext"][0]["users"][0]["flow"], "xtls-rprx-vision")
        self.assertEqual(result["streamSettings"]["realitySettings"], {
            "serverName": "cover.example.invalid", "fingerprint": "firefox",
            "publicKey": PUBLIC_KEY, "shortId": "ab12", "spiderX": "/a?b=c"
        })
        self.assertNotIn("tlsSettings", result["streamSettings"])

    def test_ws_tls_ipv6_and_encoding(self):
        result = app.parse_vless(f"vless://{UUID_1}@[2001:db8::1]:8443?" + urlencode({
                                     "security": "tls", "type": "ws", "host": "cdn.example.invalid",
                                     "path": "/a%2Fb?token=a+b&ed=2048", "alpn": "h2,http/1.1", "insecure": "0"
                                 }), app.DEFAULT_TAG)
        server = result["settings"]["vnext"][0]
        self.assertEqual((server["address"], server["port"]), ("2001:db8::1", 8443))
        self.assertEqual(result["streamSettings"]["wsSettings"], {
            "path": "/a%2Fb?token=a+b&ed=2048", "headers": {"Host": "cdn.example.invalid"}
        })
        self.assertEqual(result["streamSettings"]["tlsSettings"]["alpn"], ["h2", "http/1.1"])
        self.assertFalse(result["streamSettings"]["tlsSettings"]["allowInsecure"])

    def test_grpc(self):
        stream = app.parse_vless(link(type="grpc", security="tls", serviceName="svc/a", mode="multi",
                                      authority="grpc.example.invalid"), app.WORK_TAG)["streamSettings"]
        self.assertEqual(stream["grpcSettings"], {
            "serviceName": "svc/a", "multiMode": True, "authority": "grpc.example.invalid"
        })

    def test_xhttp_extra(self):
        extra = {"xmux": {"maxConcurrency": "8-16"}, "noGRPCHeader": True}
        stream = app.parse_vless(link(type="xhttp", security="tls", path="/tunnel", mode="stream-up",
                                      extra=json.dumps(extra)), app.WORK_TAG)["streamSettings"]
        self.assertEqual(stream["xhttpSettings"], {"path": "/tunnel", "mode": "stream-up", "extra": extra})

    def test_httpupgrade_and_raw_alias(self):
        stream = app.parse_vless(link(type="httpupgrade", security="tls", path="/up"), app.WORK_TAG)["streamSettings"]
        self.assertEqual(stream["httpupgradeSettings"], {"path": "/up"})
        stream = app.parse_vless(link(type="raw", security="none"), app.WORK_TAG)["streamSettings"]
        self.assertEqual(stream, {"network": "tcp", "security": "none"})

    def test_escaped_scheme(self):
        self.assertEqual(app.parse_vless(link().replace("vless:", "vless\\:"), app.WORK_TAG),
                         app.parse_vless(link(), app.WORK_TAG))

    def test_display_name_is_ignored(self):
        self.assertEqual(app.parse_vless(link().replace("#Test", "#Рабочий VPN 100%"), app.WORK_TAG),
                         app.parse_vless(link(), app.WORK_TAG))

    def test_bad_links_and_unsupported_options(self):
        invalid = [
            "https://example.invalid", link(user="not-a-uuid"),
            link().replace(":443?", ":70000?"), link().replace(":443?", "?"),
            link().replace("#Test", "&sni=%ZZ"), link(type="unknown"), link(security="tls", type="ws", flow="xtls-rprx-vision"),
            link(security="reality", sni="cover.example.invalid", pbk="bad"),
            link(security="reality", sni="cover.example.invalid", pbk=PUBLIC_KEY, sid="abc"),
            link(security="reality", pbk=PUBLIC_KEY), link(security="tls", insecure="maybe"),
            link(security="tls", insecure="0", allowInsecure="1"), link(type="xhttp", extra="[]"),
            link(type="xhttp", extra='{"value": NaN}'), link(type="grpc", mode="guna"),
            link(security="tls", customSetting="SECRET"), link(security="tls", headerType="http"),
            link().replace("#Test", "&security=reality#Test"),
        ]
        for uri in invalid:
            with self.subTest(uri=uri), self.assertRaises(ValueError):
                app.parse_vless(uri, app.WORK_TAG)


class BuildTests(unittest.TestCase):
    def setUp(self):
        self.template = json.loads((app.ROOT / "happ-two-vless.json").read_text())

    def test_template_selection(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(app, "ROOT", Path(folder)):
            (app.ROOT / "happ-two-vless.json").write_text(json.dumps(self.template))
            self.assertEqual(app.load_template(), self.template)
            local = copy.deepcopy(self.template)
            local["routing"]["rules"].insert(0, {
                "type": "field", "domain": ["domain:local.example.invalid"], "outboundTag": "direct"
            })
            local_path = app.ROOT / "happ-two-vless.local.json"
            local_path.write_text(json.dumps(local))
            self.assertEqual(app.load_template(), local)
            local_path.write_text("invalid JSON")
            with self.assertRaises(ValueError):
                app.load_template()

    def test_only_outbounds_and_title_change(self):
        original = copy.deepcopy(self.template)
        first = app.parse_vless(link(), app.WORK_TAG)
        second = app.parse_vless(link(host="two.example.invalid", user=UUID_2), app.DEFAULT_TAG)
        result = app.build_config(self.template, first, second)
        self.assertEqual(self.template, original)
        for key in ("routing", "dns", "inbounds", "log"):
            self.assertEqual(result[key], original[key])
        self.assertEqual(result["outbounds"], [second, first, original["outbounds"][2]])

    def test_missing_template_tag(self):
        self.template["outbounds"].pop(0)
        with self.assertRaises(ValueError):
            app.build_config(self.template, {}, {})

    def test_new_filename_permissions_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(app, "ROOT", Path(folder)):
            first = app.save_config({"value": 1})
            second = app.save_config({"value": 2})
            self.assertNotEqual(first, second)
            self.assertEqual(json.loads(first.read_text()), {"value": 1})
            if os.name == "posix":
                self.assertEqual(first.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(ValueError):
                app.save_config({"value": 3}, first)
            self.assertEqual(json.loads(first.read_text()), {"value": 1})

    def test_cli_retries_bad_input_and_saves_from_other_directory(self):
        first = link()
        second = link(host="two.example.invalid", user=UUID_2, type="grpc", security="tls", serviceName="svc")
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "result.json"
            script = Path(folder) / "build_happ_config.py"
            script.write_bytes((app.ROOT / "build_happ_config.py").read_bytes())
            (Path(folder) / "happ-two-vless.json").write_text(json.dumps(self.template))
            result = subprocess.run(
                [sys.executable, str(script), "--output", str(output)],
                input="bad\n" + first + "\n" + second + "\n", text=True, capture_output=True, cwd=app.ROOT)
            self.assertEqual(result.returncode, 0, result.stderr)
            config = json.loads(output.read_text())
            self.assertEqual(config["routing"], self.template["routing"])
            self.assertEqual(config["outbounds"][0]["settings"]["vnext"][0]["users"][0]["id"], UUID_2)
            self.assertEqual(config["outbounds"][1]["settings"]["vnext"][0]["users"][0]["id"], UUID_1)
            self.assertNotIn(UUID_1, result.stdout + result.stderr)
            self.assertNotIn(UUID_2, result.stdout + result.stderr)

    def test_eof_creates_no_file(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "result.json"
            result = subprocess.run(
                [sys.executable, str(app.ROOT / "build_happ_config.py"), "--output", str(output)],
                input=link() + "\n", text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
