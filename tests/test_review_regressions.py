from pathlib import Path

from custom_components.secretsentry.rules import R004SecretRefMissing, ScanContext


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
