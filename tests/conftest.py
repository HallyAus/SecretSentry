"""Load pure scanner modules without starting the Home Assistant integration."""

import sys
from pathlib import Path
from types import ModuleType


integration = ModuleType("custom_components.secretsentry")
integration.__path__ = [str(Path(__file__).resolve().parents[1] / "custom_components" / "secretsentry")]
sys.modules.setdefault("custom_components.secretsentry", integration)
