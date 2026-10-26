import pytest

from peaso import source_attestation_mode as mode


@pytest.fixture
def fresh(monkeypatch):
    monkeypatch.setattr(mode, "_ONCE", {})
    return mode


def test_production_reuses_a_successful_proof(fresh, monkeypatch):
    monkeypatch.setattr(fresh, "ALWAYS", False)
    calls = []

    def verifier(**kwargs):
        calls.append(kwargs)

    for _ in range(5):
        fresh.prove_once(verifier, verify_cases=False)
    assert calls == [{"verify_cases": False}]
    # Different arguments are a different proof.
    fresh.prove_once(verifier)
    assert len(calls) == 2


def test_always_mode_reproves_every_call(fresh, monkeypatch):
    monkeypatch.setattr(fresh, "ALWAYS", True)
    calls = []
    for _ in range(3):
        fresh.prove_once(lambda: calls.append(1))
    assert len(calls) == 3


def test_failed_proof_is_never_cached(fresh, monkeypatch):
    monkeypatch.setattr(fresh, "ALWAYS", False)
    attempts = []

    def verifier():
        attempts.append(1)
        raise RuntimeError("source changed")

    for _ in range(2):
        with pytest.raises(RuntimeError, match="source changed"):
            fresh.prove_once(verifier)
    assert len(attempts) == 2
    assert fresh._ONCE == {}
