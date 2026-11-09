import json
import sqlite3

import pytest

from bt_api_risk.core.admission import AccountScope
from bt_api_risk.gateway_delegate_journal import RiskGatewayDelegateJournal
from bt_api_risk.risk_order_journal import RiskOrderJournal
from bt_api_risk.risk_order_journal_contracts import RiskOrderJournalError


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def test_reopen_conflicts_monotonic_observations_and_fence(tmp_path):
    path = tmp_path / "risk.sqlite"
    scope = AccountScope("test", "account", "paper")
    journal = RiskOrderJournal(path, writer_id="risk")
    intent = encoded({"actor": "risk", "request": "r1"})
    marker = encoded(["reservation", "digest", 1, "command"])
    with journal.writer_fence(scope) as fence:
        host = RiskGatewayDelegateJournal(journal, fence)
        assert host.account_scope == scope
        assert host.load("intent", "r1") is None
        assert host.save("intent", "r1", intent) == intent
        assert host.save("intent", "r1", intent) == intent
        with pytest.raises(RiskOrderJournalError, match="DELEGATE_RECORD_CONFLICT"):
            host.save("intent", "r1", encoded({"actor": "other"}))
        host.save("observation", "r1", encoded({"state": "RESERVED"}), version=1)
        host.save("dispatch_marker", "r1", marker)
        cancel = encoded({"operation_id": "cancel-1", "request_key": "r1"})
        host.save("cancel_intent", "cancel-1", cancel)
        host.save("cancel_dispatch_marker", "cancel-1", encoded(["attempt-1"]))
        host.save("cancel_observation", "cancel-1", encoded({"state": "SENT"}), version=1)
        release = encoded({"operation_id": "release-1", "request_key": "r1"})
        host.save("release_intent", "release-1", release)
        host.save("release_marker", "release-1", encoded(["attempt-1"]))
        host.save("release_observation", "release-1", encoded({"state": "RELEASED"}), version=1)
        host.save("observation", "r1", encoded({"state": "SENT"}), version=3)
        for version, state in ((1, "RESERVED"), (3, "UNKNOWN")):
            with pytest.raises(RiskOrderJournalError, match="DELEGATE_RECORD_CONFLICT"):
                host.save("observation", "r1", encoded({"state": state}), version=version)
    with pytest.raises(RiskOrderJournalError, match="WRITER_FENCE_NOT_HELD"):
        host.load("intent", "r1")
    with pytest.raises(RiskOrderJournalError, match="WRITER_FENCE_NOT_HELD"):
        _ = host.account_scope
    reopened = RiskOrderJournal(path, writer_id="risk-restarted")
    with reopened.writer_fence(scope) as fence:
        resumed = RiskGatewayDelegateJournal(reopened, fence)
        assert resumed.load("intent", "r1") == intent
        assert resumed.load("dispatch_marker", "r1") == marker
        assert resumed.load("cancel_intent", "cancel-1") == cancel
        assert resumed.load("cancel_dispatch_marker", "cancel-1") == encoded(["attempt-1"])
        assert resumed.load("cancel_observation", "cancel-1") == encoded({"state": "SENT"})
        assert resumed.load("release_intent", "release-1") == release
        assert resumed.load("release_marker", "release-1") == encoded(["attempt-1"])
        assert resumed.load("release_observation", "release-1") == encoded({"state": "RELEASED"})
        with pytest.raises(RiskOrderJournalError, match="DELEGATE_RECORD_CONFLICT"):
            resumed.save("release_marker", "release-1", encoded(["attempt-2"]))
        assert resumed.load("observation", "r1") == encoded({"state": "SENT"})
        with pytest.raises(RiskOrderJournalError, match="DELEGATE_RECORD_CONFLICT"):
            resumed.save("dispatch_marker", "r1", encoded(["other"]))
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT value FROM risk_order_meta WHERE key='schema_version'").fetchone() == ("1",)
        assert connection.execute("SELECT schema_version FROM risk_gateway_delegate_meta").fetchone() == (1,)
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("DELETE FROM risk_gateway_delegate_records")


def test_extension_fails_closed_for_unknown_version_and_bad_payload(tmp_path):
    path = tmp_path / "risk.sqlite"
    scope = AccountScope("test", "account", "paper")
    journal = RiskOrderJournal(path, writer_id="risk")
    with journal.writer_fence(scope) as fence:
        host = RiskGatewayDelegateJournal(journal, fence)
        for kind, version in (("observation", 1), ("dispatch_marker", 0),
                              ("release_marker", 0), ("release_observation", 1)):
            with pytest.raises(RiskOrderJournalError, match="DELEGATE_PREDECESSOR_REQUIRED"):
                host.save(kind, "missing", '{}', version=version)
        for value in ('{"b": 1}', '{"x":NaN}', '42'):
            with pytest.raises(RiskOrderJournalError, match="DELEGATE_INVALID_PAYLOAD"):
                host.save("intent", "r", value)
        with pytest.raises(RiskOrderJournalError, match="DELEGATE_INVALID_VERSION"):
            host.save("observation", "r", '{}')
    with journal.writer_fence(scope) as fence:
        active = RiskGatewayDelegateJournal(journal, fence)
        with sqlite3.connect(path) as connection:
            connection.execute("UPDATE risk_gateway_delegate_meta SET schema_version=2")
        with pytest.raises(RiskOrderJournalError, match="DELEGATE_SCHEMA_MISMATCH"):
            active.load("intent", "r")
        with pytest.raises(RiskOrderJournalError, match="DELEGATE_SCHEMA_MISMATCH"):
            RiskGatewayDelegateJournal(journal, fence)


def test_separate_accounts_and_journal_owners_cannot_share_fence(tmp_path):
    path = tmp_path / "risk.sqlite"
    first = RiskOrderJournal(path, writer_id="first")
    second = RiskOrderJournal(path, writer_id="second")
    account_a = AccountScope("test", "a", "paper")
    account_b = AccountScope("test", "b", "paper")
    with first.writer_fence(account_a) as fence:
        first_host = RiskGatewayDelegateJournal(first, fence)
        first_host.save("intent", "same-key", encoded({"account": "a"}))
        with pytest.raises(RiskOrderJournalError, match="DELEGATE_WRITER_NOT_OWNED"):
            RiskGatewayDelegateJournal(second, fence)
        with first.writer_fence(account_b) as other:
            second_host = RiskGatewayDelegateJournal(first, other)
            assert second_host.load("intent", "same-key") is None
            second_host.save("intent", "same-key", encoded({"account": "b"}))
        assert first_host.load("intent", "same-key") == encoded({"account": "a"})
