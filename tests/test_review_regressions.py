import asyncio
import sys
from pathlib import Path
from types import ModuleType

from custom_components.secretsentry.rules import R004SecretRefMissing, ScanContext
from custom_components.secretsentry.scanner import SecretSentryScanner


def make_context():
    return ScanContext(
        config_root=Path('.'),
        secrets_map={'root_key': '***'},
        secrets_raw_hashes={},
        used_secret_keys=set(),
        gitignore_text=None,
        options={},
        secret_store_keys={'.': {'root_key'}, 'esphome': {'wifi_key'}},
    )


def test_nested_secret_store_does_not_satisfy_sibling_reference():
    context = make_context()
    rule = R004SecretRefMissing()
    rule.evaluate_file_text('packages/foo.yaml', ['password: !secret wifi_key'], context)
    findings = rule.evaluate_context(context)
    assert len(findings) == 1
    assert findings[0].file_path == 'packages/foo.yaml'


def test_nested_secret_store_satisfies_own_subtree_and_root_fallback():
    context = make_context()
    rule = R004SecretRefMissing()
    rule.evaluate_file_text('esphome/device.yaml', [
        'password: !secret wifi_key',
        'token: !secret root_key',
    ], context)
    assert rule.evaluate_context(context) == []


def test_scan_uses_nested_secret_store_and_skips_managed_credentials(tmp_path):
    (tmp_path / "secrets.yaml").write_text(
        "root_key: https://user:password@example.com\n", encoding="utf-8"
    )
    esphome = tmp_path / "esphome"
    esphome.mkdir()
    (esphome / "secrets.yaml").write_text(
        "wifi_key: this-is-a-secret-value\n", encoding="utf-8"
    )
    (esphome / "device.yaml").write_text(
        "password: !secret wifi_key\ntoken: !secret root_key\n", encoding="utf-8"
    )
    managed = tmp_path / ".cloud"
    managed.mkdir()
    (managed / "credentials.yaml").write_text(
        "password: leaked-managed-secret-value\n", encoding="utf-8"
    )

    result = SecretSentryScanner(str(tmp_path), {"enable_env_hygiene": False}).scan()

    assert not any(f.rule_id == "R004" for f in result.findings)
    assert not any(f.file_path.startswith(".cloud") for f in result.findings)
    assert not any(f.file_path == "secrets.yaml" and f.rule_id != "R060" for f in result.findings)
    assert "esphome" in SecretSentryScanner(str(tmp_path))._create_context(set()).secret_store_keys


def test_external_check_options_require_a_valid_url_when_enabled(monkeypatch):
    """The new option is reachable and cannot enable a malformed target."""
    homeassistant = ModuleType("homeassistant")
    homeassistant.__path__ = []
    config_entries = ModuleType("homeassistant.config_entries")
    core = ModuleType("homeassistant.core")

    class ConfigFlow:
        def __init_subclass__(cls, **kwargs):
            pass

    class OptionsFlow:
        def async_show_form(self, **kwargs):
            return {"type": "form", **kwargs}

        def async_create_entry(self, **kwargs):
            return {"type": "entry", **kwargs}

    config_entries.ConfigEntry = type("ConfigEntry", (), {})
    config_entries.ConfigFlow = ConfigFlow
    config_entries.OptionsFlow = OptionsFlow
    core.callback = lambda function: function
    monkeypatch.setitem(sys.modules, "homeassistant", homeassistant)
    monkeypatch.setitem(sys.modules, "homeassistant.config_entries", config_entries)
    monkeypatch.setitem(sys.modules, "homeassistant.core", core)

    from custom_components.secretsentry.config_flow import SecretSentryOptionsFlowHandler
    from custom_components.secretsentry.const import CONF_ENABLE_EXTERNAL_CHECK, CONF_EXTERNAL_URL

    entry = type("Entry", (), {"options": {}})()
    flow = SecretSentryOptionsFlowHandler(entry)
    form = asyncio.run(flow.async_step_settings())
    submitted = form["data_schema"]({})
    assert CONF_ENABLE_EXTERNAL_CHECK in submitted
    assert CONF_EXTERNAL_URL in submitted

    submitted[CONF_ENABLE_EXTERNAL_CHECK] = True
    submitted[CONF_EXTERNAL_URL] = "not-a-url"
    invalid = asyncio.run(flow.async_step_settings(submitted))
    assert invalid["errors"] == {CONF_EXTERNAL_URL: "invalid_url"}

    submitted[CONF_EXTERNAL_URL] = "https://example.com"
    valid = asyncio.run(flow.async_step_settings(submitted))
    assert valid["type"] == "entry"
    assert valid["data"][CONF_EXTERNAL_URL] == "https://example.com"
