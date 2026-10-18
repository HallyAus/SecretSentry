#!/usr/bin/env bash
set -euo pipefail
unset SOURCE_TOKEN GITEA_TOKEN GITHUB_TOKEN
python .gitea/scripts/verify-source.py
python -m pip install --disable-pip-version-check pytest==9.1.1 pytest-socket==0.8.1 aiohttp==3.14.5 voluptuous==0.16.0 PyYAML==6.0.3
python -m pytest tests/ -q --disable-socket --allow-unix-socket
