"""Fresh-process admission must not depend on analytical or provider imports."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

import bt_api_risk


@pytest.mark.parametrize("entry", ["bt_api_risk", "bt_api_risk.core"])
def test_durable_admission_works_when_analytical_imports_are_forbidden(tmp_path, entry):
    base_spec = importlib.util.find_spec("bt_api_base")
    assert base_spec is not None and base_spec.origin is not None
    paths = [
        str(Path(bt_api_risk.__file__).resolve().parent.parent),
        str(Path(base_spec.origin).resolve().parent.parent),
    ]
    script = r"""
import importlib
import importlib.abc
import sys
from decimal import Decimal

sys.path[:0] = __import__("json").loads(sys.argv[1])
blocked = {"numpy", "scipy", "sklearn", "pandas", "bt_api_py", "bt_api_ctp"}

class NoAnalysisOrProvider(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split(".")[0] in blocked:
            raise AssertionError("unexpected admission import: " + fullname)

sys.meta_path.insert(0, NoAnalysisOrProvider())
def no_external_io(event, args):
    if event in {"socket.connect", "socket.bind", "socket.getaddrinfo", "socket.sendto"}:
        raise AssertionError("admission performed socket I/O")
sys.addaudithook(no_external_io)
module = importlib.import_module(sys.argv[2])
assert "RiskManager" in dir(module)
assert "RiskManager" not in vars(module)
scope = module.AccountScope(provider="fake", account_id="import-test", environment="sandbox")
policy = module.RiskPolicy(
    policy_id="import-test", max_increase_notional=Decimal("100"), max_increase_count=3,
)
gate = module.DurableRiskGate(sys.argv[3], policy)
try:
    intent = module.RiskIntent(
        intent_id="intent-1", scope=scope, action=module.IntentAction.INCREASE,
        notional=Decimal("10"), payload_fingerprint="synthetic-import-test",
    )
    permit = gate.reserve(intent)
    assert permit.intent_id == "intent-1"
finally:
    gate.close()
assert not (blocked & {name.split(".")[0] for name in sys.modules})
"""
    result = subprocess.run(  # noqa: S603 -- fixed interpreter/script and synthetic local arguments.
        [sys.executable, "-I", "-c", script, json.dumps(paths), entry, str(tmp_path / "risk.db")],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_lazy_exports_keep_established_types_and_missing_attribute_errors():
    from bt_api_risk import AnomalyDetector, RiskAssessor, RiskEnsembleModel, RiskManager
    from bt_api_risk.core import LimitsManager, PolicyEngine, RiskCalculator
    from bt_api_risk.core.risk_manager import RiskManager as Implementation

    assert RiskManager is Implementation
    for exported in (
        AnomalyDetector,
        RiskAssessor,
        RiskEnsembleModel,
        LimitsManager,
        PolicyEngine,
        RiskCalculator,
    ):
        assert isinstance(exported, type)
    with pytest.raises(AttributeError, match="unknown_public_name"):
        _ = bt_api_risk.unknown_public_name
