from __future__ import annotations

import json
import os
import subprocess
import sysconfig
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest


class MockShodanHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        content = b'{"banner":true}\n' if self.path.startswith("/shodan/banners") else b'{"mocked":true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, _format: str, *_args: object) -> None:
        return


@contextmanager
def mock_server() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), MockShodanHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


GROUP_SMOKES = [
    ["host", "info", "192.0.2.1"],
    ["search", "count", "nginx"],
    ["scan", "list"],
    ["alert", "list"],
    ["notifier", "list"],
    ["query", "tags"],
    ["dns", "resolve", "example.com"],
    ["tools", "myip"],
    ["account", "profile"],
    ["stream", "banners", "--limit", "1"],
    ["trends", "filters"],
    ["exploits", "count", "apache"],
    ["data", "list"],
    ["org", "info"],
    ["reference", "filters"],
]


@pytest.mark.parametrize("args", GROUP_SMOKES)
def test_installed_entrypoint_representative_group_smokes(tmp_path: Path, args: list[str]) -> None:
    suffix = ".exe" if os.name == "nt" else ""
    configured = os.environ.get("SHODAN_SKILL_CONSOLE")
    executable = Path(configured) if configured else Path(sysconfig.get_path("scripts")) / f"shodan-skill{suffix}"
    assert executable.is_file()
    with mock_server() as base_url:
        sitecustomize = tmp_path / "sitecustomize.py"
        sitecustomize.write_text(
            "import shodan_skill.transport as transport\n"
            f"transport.BASE_URLS = {{name: {base_url!r} for name in transport.BASE_URLS}}\n",
            encoding="utf-8",
        )
        env = os.environ.copy()
        env["SHODAN_API_KEY"] = "installed-contract-key"
        env["PYTHONPATH"] = str(tmp_path) + os.pathsep + env.get("PYTHONPATH", "")
        result = subprocess.run(
            [str(executable), *args],
            env=env,
            text=True,
            capture_output=True,
            timeout=15,
            check=False,
        )
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    payload = json.loads(result.stdout.splitlines()[0] if args[0] == "stream" else result.stdout)
    assert payload["ok"] is True
