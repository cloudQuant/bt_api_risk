"""Optional local operator Web API of the Risk service (iteration 64, step 64.13 interface).

``bt_api_risk.web.app`` is an HTTP adapter in front of the Risk service's operator
port ``service.risk_admin``. It needs the ``web`` extra (FastAPI); importing this
package does not import FastAPI, and ``bt_api_risk`` and ``bt_api_risk.pretrade``
never import this package. The adapter holds no risk state and grants nothing:
every call is made by a host-supplied caller over the operator's own
authenticated registration, and the Risk service authorizes and audits it.
"""

from __future__ import annotations

from importlib import import_module

_EXPORTS = frozenset(
    {
        "API_PREFIX",
        "AuthenticatedRiskSession",
        "CancelRequest",
        "LatchReleaseRequest",
        "PolicyPublishRequest",
        "RiskAdminCallError",
        "create_app",
        "run_local",
    }
)

__all__ = sorted(_EXPORTS)


def __getattr__(name: str):
    if name in _EXPORTS:
        return getattr(import_module(".app", __name__), name)
    raise AttributeError(name)
