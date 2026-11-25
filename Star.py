"""Start the local SIEM analyzer, including Ollama when needed."""

import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

import requests
from waitress import serve

sys.path.insert(0, str(Path(__file__).resolve().parent / "ai_module"))

from dashboard import DEFAULT_CONFIG, _dashboard_cfg, _dependency_health, create_app, load_config
from reader import _is_loopback_host


def ollama_ready(base_url):
    try:
        response = requests.get(f"{base_url}/api/tags", timeout=2, allow_redirects=False)
        if response.status_code == 200:
            tags = response.json()
            return isinstance(tags, dict) and isinstance(tags.get("models"), list)
    except (requests.RequestException, ValueError):
        pass
    return False


def start():
    if not DEFAULT_CONFIG.is_file():
        raise SystemExit("Missing ai_module/config.yaml. See the setup section in README.md.")
    cfg = load_config(DEFAULT_CONFIG)
    # Fixed policy: security tests are always enabled when launched via Star.py.
    # Merge (not replace) so attacker/victim/SSH settings from config.yaml survive;
    # the runner refuses to run without them.
    cfg["security_tests"] = {**(cfg.get("security_tests") or {}), "enabled": True}
    base_url = cfg["ollama"].get("base_url", "").rstrip("/")
    if not base_url:
        raise SystemExit("Set ollama.base_url in ai_module/config.yaml.")

    settings = _dashboard_cfg(cfg)
    host, port = settings["host"], settings["port"]
    ollama = None
    with socket.socket() as listener:
        # Reserve the port before dashboard startup recovers jobs in SQLite.
        socket_option = getattr(socket, "SO_EXCLUSIVEADDRUSE", socket.SO_REUSEADDR)
        listener.setsockopt(socket.SOL_SOCKET, socket_option, 1)
        try:
            listener.bind((host, port))
        except OSError as exc:
            raise SystemExit(f"Cannot bind dashboard to {host}:{port} ({exc.strerror}).") from None

        try:
            if not ollama_ready(base_url):
                url = urlsplit(base_url)
                # ponytail: start native loopback HTTP only. Manage proxied or remote Ollama separately.
                if url.scheme != "http" or url.path or not _is_loopback_host(url.hostname):
                    raise SystemExit("Configured Ollama is unavailable. Start it on its configured host.")
                try:
                    listen = url.netloc if url.port is not None else f"{url.netloc}:80"
                    ollama = subprocess.Popen(["ollama", "serve"], env={**os.environ, "OLLAMA_HOST": listen})
                except FileNotFoundError:
                    raise SystemExit("Ollama is required. Install it and add it to PATH.") from None
                deadline = time.monotonic() + 30
                while not ollama_ready(base_url):
                    if ollama.poll() is not None:
                        raise SystemExit(f"Ollama exited with code {ollama.returncode} before becoming ready.")
                    if time.monotonic() >= deadline:
                        raise SystemExit("Ollama did not become ready within 30 seconds.")
                    time.sleep(0.5)

            print(f'Wazuh Indexer: {_dependency_health(cfg)["indexer"]["status"]}', flush=True)
            serve(create_app(cfg=cfg), sockets=[listener])
        finally:
            if ollama is not None and ollama.poll() is None:
                ollama.terminate()
                try:
                    ollama.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    ollama.kill()
                    ollama.wait()


if __name__ == "__main__":
    start()
