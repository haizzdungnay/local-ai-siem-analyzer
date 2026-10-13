"""tests/test_lab_preflight_check.py

Kiểm thử đơn vị cho script kiểm tra tiền trạm phòng lab scripts/lab_preflight_check.py.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import lab_preflight_check as lpc  # noqa: E402


def test_load_lab_config_existing_file(tmp_path: Path):
    cfg_file = tmp_path / "custom_config.yaml"
    cfg_file.write_text("ollama:\n  base_url: 'http://127.0.0.1:11434'\n", encoding="utf-8")
    loaded = lpc.load_lab_config(cfg_file)
    assert loaded["ollama"]["base_url"] == "http://127.0.0.1:11434"


def test_load_lab_config_missing_file_fallback():
    missing_file = ROOT / "non_existent_config.yaml"
    loaded = lpc.load_lab_config(missing_file)
    # Falls back to config.example.yaml
    assert isinstance(loaded, dict)
    assert "ollama" in loaded


def test_check_tcp_port_success():
    with patch("socket.create_connection") as mock_conn:
        mock_conn.return_value.__enter__.return_value = MagicMock()
        res = lpc.check_tcp_port("127.0.0.1", 80, timeout=1.0)
        assert res["reachable"] is True
        assert res["error"] is None


def test_check_tcp_port_failure():
    with patch("socket.create_connection", side_effect=OSError("Connection refused")):
        res = lpc.check_tcp_port("127.0.0.1", 80, timeout=1.0)
        assert res["reachable"] is False
        assert "Connection refused" in res["error"]


def test_check_ollama_tcp_unreachable():
    with patch.object(lpc, "check_tcp_port", return_value={"reachable": False, "error": "Refused"}):
        res = lpc.check_ollama("http://127.0.0.1:11434")
        assert res["status"] == "FAIL"
        assert "TCP unreachable" in res["details"]


def test_check_ollama_all_models_present():
    with patch.object(lpc, "check_tcp_port", return_value={"reachable": True, "error": None}):
        fake_resp = MagicMock()
        fake_resp.json.return_value = {
            "models": [
                {"name": "qwen2.5:7b"},
                {"name": "qwen2.5:3b"},
                {"name": "nomic-embed-text:latest"},
            ]
        }
        with patch("requests.get", return_value=fake_resp):
            res = lpc.check_ollama("http://127.0.0.1:11434")
            assert res["status"] == "PASS"
            assert res["missing_recommended"] == []


def test_check_ollama_missing_models():
    with patch.object(lpc, "check_tcp_port", return_value={"reachable": True, "error": None}):
        fake_resp = MagicMock()
        fake_resp.json.return_value = {"models": [{"name": "qwen2.5:3b"}]}
        with patch("requests.get", return_value=fake_resp):
            res = lpc.check_ollama("http://127.0.0.1:11434")
            assert res["status"] == "WARN"
            assert "qwen2.5:7b" in res["missing_recommended"]


def test_check_wazuh_indexer_change_me_warn():
    with patch.object(lpc, "check_tcp_port", return_value={"reachable": True, "error": None}):
        res = lpc.check_wazuh_indexer({"host": "127.0.0.1", "port": 9200, "password": "CHANGE_ME"})
        assert res["status"] == "WARN"
        assert "CHANGE_ME" in res["details"]


def test_check_wazuh_indexer_success():
    with patch.object(lpc, "check_tcp_port", return_value={"reachable": True, "error": None}):
        fake_resp = MagicMock()
        fake_resp.json.return_value = {
            "cluster_name": "wazuh-cluster",
            "status": "green",
            "number_of_nodes": 1,
        }
        with patch("requests.get", return_value=fake_resp):
            res = lpc.check_wazuh_indexer({"host": "127.0.0.1", "port": 9200, "password": "valid_pwd"})
            assert res["status"] == "PASS"
            assert res["cluster_status"] == "green"


def test_check_wazuh_indexer_auth_failure():
    with patch.object(lpc, "check_tcp_port", return_value={"reachable": True, "error": None}):
        err_resp = MagicMock(status_code=401)
        http_err = requests.exceptions.HTTPError(response=err_resp)
        with patch("requests.get", side_effect=http_err):
            res = lpc.check_wazuh_indexer({"host": "127.0.0.1", "port": 9200, "password": "wrong"})
            assert res["status"] == "FAIL"
            assert "Sai thông tin đăng nhập" in res["details"]


def test_check_wazuh_manager_success():
    with patch.object(lpc, "check_tcp_port", return_value={"reachable": True, "error": None}):
        fake_resp = MagicMock()
        fake_resp.json.return_value = {"data": {"token": "jwt-token-123"}}
        with patch("requests.post", return_value=fake_resp):
            res = lpc.check_wazuh_manager({"host": "127.0.0.1", "port": 55000, "password": "valid"})
            assert res["status"] == "PASS"
            assert res["token"] == "jwt-token-123"


def test_check_wazuh_manager_change_me_warn():
    with patch.object(lpc, "check_tcp_port", return_value={"reachable": True, "error": None}):
        res = lpc.check_wazuh_manager({"host": "127.0.0.1", "port": 55000, "password": "CHANGE_ME"})
        assert res["status"] == "WARN"
        assert res["token"] is None


def test_check_wazuh_agents_skip_without_token():
    res = lpc.check_wazuh_agents({}, None)
    assert res["status"] == "SKIP"


def test_check_wazuh_agents_parse_victim():
    fake_resp = MagicMock()
    fake_resp.json.return_value = {
        "data": {
            "affected_items": [
                {"id": "001", "name": "victim-ubuntu", "ip": "192.168.100.20", "status": "active"},
                {"id": "002", "name": "victim-windows", "ip": "192.168.100.40", "status": "active"},
            ]
        }
    }
    with patch("requests.get", return_value=fake_resp):
        res = lpc.check_wazuh_agents({"host": "127.0.0.1"}, "dummy-token")
        assert res["status"] == "PASS"
        assert res["ubuntu_victim_20"] == "active"
        assert "active" in res["windows_victim_40"]
        assert "Sysmon: Chưa xác nhận" in res["windows_victim_40"]


def test_run_preflight_and_formatting(tmp_path: Path):
    cfg_file = tmp_path / "test_cfg.yaml"
    cfg_file.write_text("ollama: {}\nwazuh: {}\nwazuh_indexer: {}\n", encoding="utf-8")

    with patch.object(lpc, "check_ollama", return_value={"service": "Ollama", "status": "PASS", "details": "ok"}), \
         patch.object(lpc, "check_wazuh_indexer", return_value={"service": "Indexer", "status": "PASS", "details": "ok"}), \
         patch.object(lpc, "check_wazuh_manager", return_value={"service": "Manager", "status": "PASS", "details": "ok", "token": "abc"}), \
         patch.object(lpc, "check_wazuh_agents", return_value={"service": "Agents", "status": "PASS", "details": "ok"}):
        report = lpc.run_preflight(cfg_file)
        assert report["overall_status"] == "PASS"
        assert "token" not in report["checks"]["wazuh_manager"]

        text = lpc.format_report_text(report)
        assert "KẾT QUẢ LAB PREFLIGHT CHECK: [PASS]" in text
        assert "Wazuh Indexer :9200" in text
