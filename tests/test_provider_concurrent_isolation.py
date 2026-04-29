"""
Tests for provider instance isolation when workflows run concurrently.

Verifies that:
1. deepcopy produces independent provider instances per WF execution.
2. Mutable state written in _query (e.g. Datadog self.to / self._from) does not
   bleed between copies.
3. Token-cache fields (e.g. Kaia self._access_token) do not bleed between copies.
4. threading.local results are isolated per thread and execution_id.
"""

import copy
import threading
import time
import uuid
from unittest.mock import MagicMock, patch

import pytest

from keep.providers.base.base_provider import BaseProvider
from keep.providers.models.provider_config import ProviderConfig


# ---------------------------------------------------------------------------
# Minimal concrete provider for unit testing (no external deps)
# ---------------------------------------------------------------------------

class _MockConfig:
    """Minimal stand-in for authentication config."""
    pass


class _TestProvider(BaseProvider):
    """Minimal concrete provider with mutable execution-time state."""

    def validate_config(self):
        self.authentication_config = _MockConfig()

    def dispose(self):
        pass

    def _query(self, value=None, **kwargs):
        # Simulates Datadog-like mutation of timestamp fields during _query
        self.last_query_value = value
        time.sleep(0.05)          # give other threads a chance to race
        return {"value": value}

    def _notify(self, **kwargs):
        return {}


def _make_provider(execution_id="exec-001"):
    """Build a provider instance with a mocked ContextManager."""
    cm = MagicMock()
    cm.tenant_id = "test-tenant"
    cm.workflow_execution_id = execution_id
    cm.foreach_context = {"value": {}}
    cm.event_context = None
    cm.incident_context = None
    cm.dependencies = set()

    config = ProviderConfig(
        name="test-provider",
        authentication={},
    )
    return _TestProvider(context_manager=cm, provider_id="test-provider", config=config)


# ---------------------------------------------------------------------------
# 1. deepcopy isolation: mutable fields are independent after copy
# ---------------------------------------------------------------------------

def test_deepcopy_produces_independent_instances():
    """Mutating state on a copy must not affect the original."""
    original = _make_provider()
    original.last_query_value = "original"

    copy_a = copy.deepcopy(original)
    copy_b = copy.deepcopy(original)

    copy_a.last_query_value = "exec-A"
    copy_b.last_query_value = "exec-B"

    assert original.last_query_value == "original", "original was mutated"
    assert copy_a.last_query_value == "exec-A"
    assert copy_b.last_query_value == "exec-B"
    # copies don't share the same object
    assert copy_a is not copy_b
    assert copy_a is not original


# ---------------------------------------------------------------------------
# 2. results isolation: thread-local + execution_id reset
# ---------------------------------------------------------------------------

def test_results_isolated_per_execution_id():
    """results must reset when execution_id changes (simulates two WF executions
    on the same provider instance before deepcopy was added)."""
    provider = _make_provider(execution_id="exec-X")
    provider.results.append("result-from-X")
    assert provider.results == ["result-from-X"]

    # Simulate a new execution on the same provider (same thread)
    provider.context_manager.workflow_execution_id = "exec-Y"
    assert provider.results == [], "results were not reset for new execution_id"


def test_results_isolated_across_threads():
    """Each thread sees its own results list (via threading.local)."""
    provider = _make_provider(execution_id="exec-main")
    provider.results.append("main-thread-result")

    thread_results_seen = {}

    def run_in_thread(exec_id, value):
        # Each thread has its own local storage; change exec_id to trigger reset
        provider.context_manager.workflow_execution_id = exec_id
        provider.results.append(value)
        thread_results_seen[exec_id] = list(provider.results)

    t1 = threading.Thread(target=run_in_thread, args=("exec-T1", "result-T1"))
    t2 = threading.Thread(target=run_in_thread, args=("exec-T2", "result-T2"))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    # Main thread still sees only its own result
    provider.context_manager.workflow_execution_id = "exec-main"
    assert provider.results == ["main-thread-result"]

    # Each worker thread only accumulated its own value
    assert thread_results_seen.get("exec-T1") == ["result-T1"]
    assert thread_results_seen.get("exec-T2") == ["result-T2"]


# ---------------------------------------------------------------------------
# 3. Datadog-style: self.to / self._from don't bleed between copies
# ---------------------------------------------------------------------------

def test_query_time_mutation_isolated_between_copies():
    """Mutations to instance fields written during _query (like Datadog's
    self.to / self._from) must not cross between independent copies."""
    original = _make_provider()

    results = {}
    errors = []

    def run_copy(label, query_value):
        try:
            p = copy.deepcopy(original)
            # Simulates Datadog-like: self.to = now; self._from = now - timeframe
            p.last_query_value = query_value
            time.sleep(0.02)
            results[label] = p.last_query_value
        except Exception as exc:
            errors.append(exc)

    t1 = threading.Thread(target=run_copy, args=("wf-1", "value-wf1"))
    t2 = threading.Thread(target=run_copy, args=("wf-2", "value-wf2"))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert not errors, f"Threads raised errors: {errors}"
    assert results["wf-1"] == "value-wf1", "wf-1 result was contaminated"
    assert results["wf-2"] == "value-wf2", "wf-2 result was contaminated"


# ---------------------------------------------------------------------------
# 4. Kaia/Zoom-style: token cache isolated between copies
# ---------------------------------------------------------------------------

def test_token_cache_isolated_between_copies():
    """Cached tokens assigned in one copy must not appear in another."""
    original = _make_provider()
    original._access_token = None
    original._token_expires_at = 0

    copy_a = copy.deepcopy(original)
    copy_b = copy.deepcopy(original)

    # Simulate token acquisition in copy_a (like Kaia._get_access_token)
    copy_a._access_token = "token-for-wf-A"
    copy_a._token_expires_at = time.time() + 3600

    # copy_b must still be None — it has its own instance
    assert copy_b._access_token is None, "Token from copy_a leaked into copy_b"
    assert copy_b._token_expires_at == 0


# ---------------------------------------------------------------------------
# 5. __setstate__ reinitialises _results_storage correctly
# ---------------------------------------------------------------------------

def test_setstate_reinitialises_results_storage():
    """After deepcopy, _results_storage must be a fresh threading.local."""
    original = _make_provider()
    original.results.append("before-copy")

    copied = copy.deepcopy(original)

    # The copy must have its own clean thread-local storage
    assert not hasattr(copied._results_storage, "value") or copied.results == [], \
        "deepcopy leaked results list from original into copy"

    # Appending to copy must not affect original
    copied.results.append("after-copy")
    assert "after-copy" not in original.results


def test_deepcopy_sanitizes_non_copyable_runtime_attributes():
    """Provider deepcopy must not fail when runtime attributes are not copyable
    (for example objects that include threading.local)."""
    provider = _make_provider()
    provider.runtime_cache = threading.local()
    provider.runtime_cache.value = "unsafe"

    copied = copy.deepcopy(provider)

    assert copied is not provider
    assert getattr(copied, "runtime_cache", None) is None


# ---------------------------------------------------------------------------
# 6. Concurrent deepcopy from a single cached template (workflowstore pattern)
# ---------------------------------------------------------------------------

def test_concurrent_deepcopy_from_shared_template():
    """Simulates WorkflowStore.get_payload: multiple threads deepcopy the same
    cached provider template simultaneously — no cross-contamination in results."""
    template = _make_provider()

    errors = []
    per_wf_results = {}
    lock = threading.Lock()

    def simulate_wf_execution(exec_id):
        try:
            # Mimics workflowstore deepcopy per execution
            provider = copy.deepcopy(template)
            provider.context_manager.workflow_execution_id = exec_id
            provider.results.append(f"result-of-{exec_id}")
            time.sleep(0.05)
            final = list(provider.results)
            with lock:
                per_wf_results[exec_id] = final
        except Exception as exc:
            errors.append(exc)

    threads = [
        threading.Thread(target=simulate_wf_execution, args=(f"exec-{i}",))
        for i in range(6)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"Threads raised errors: {errors}"
    for exec_id, res in per_wf_results.items():
        assert res == [f"result-of-{exec_id}"], \
            f"{exec_id} had contaminated results: {res}"
