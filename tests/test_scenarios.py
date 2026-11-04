import pytest
from biosentinel import scenarios
from biosentinel.runner import fresh_sentinel, run_scenario, detection_steps

NAMES = list(scenarios.SCENARIOS)


@pytest.mark.parametrize("name", NAMES)
@pytest.mark.parametrize("seed", [0, 1, 2])
def test_gradual_attack_quarantined_before_breach(name, seed):
    sc = scenarios.build(name, seed)
    warn, quar = detection_steps(run_scenario(sc, fresh_sentinel()))
    assert quar is not None and quar < sc.breach_step, (warn, quar, sc.breach_step)


@pytest.mark.parametrize("name", NAMES)
def test_stealth_attack_still_caught_quickly(name):
    sc = scenarios.build(name, 0, stealth=True)
    _, quar = detection_steps(run_scenario(sc, fresh_sentinel()))
    assert quar is not None and quar <= sc.breach_step + 2


def test_no_false_quarantine_on_benign_even_in_noisy_env():
    for seed in range(15):
        sc = scenarios.build(None, seed, noisy_env=seed % 2 == 0)
        _, quar = detection_steps(run_scenario(sc, fresh_sentinel()))
        assert quar is None, seed


def test_quarantined_agent_is_blocked_at_gateway():
    s = fresh_sentinel()
    sc = scenarios.build("poisoned_dependency", 0)
    run_scenario(sc, s)
    assert s.allow_tool_call(sc.events[0].agent_id) is False


def test_baseline_not_poisoned_by_attack_steps():
    s = fresh_sentinel()
    sc = scenarios.build("poisoned_dependency", 0)
    run_scenario(sc, s)
    snap = s.profile.snapshot(sc.events[0].agent_id)
    assert "metrics.pkg-updates.example" not in snap["external_destinations"]
