from __future__ import annotations

import inspect

from phoenix_os.browser_automation import BrowserAutomationService


def test_browser_effect_pipeline_has_no_observer_wait_after_final_admission() -> None:
    for method in (
        BrowserAutomationService.navigate,
        BrowserAutomationService.fill_element,
        BrowserAutomationService.click_element,
    ):
        critical = inspect.getsource(inspect.unwrap(method))
        assert "_record_observation" not in critical
        assert "observer" not in critical.lower()

    record = inspect.getsource(BrowserAutomationService._record_observation)
    assert inspect.iscoroutinefunction(BrowserAutomationService._record_observation) is False
    assert "create_task" in record


def test_browser_health_and_observation_helpers_do_not_enter_commit_pipeline() -> None:
    click = inspect.getsource(inspect.unwrap(BrowserAutomationService.click_element))
    navigate = inspect.getsource(inspect.unwrap(BrowserAutomationService.navigate))
    fill = inspect.getsource(inspect.unwrap(BrowserAutomationService.fill_element))

    assert "_run_final_admission" in click
    assert "_adapter.commit_click_request" in click
    assert "_run_final_admission" in navigate
    assert "_adapter.commit_navigation" in navigate
    assert "_run_final_admission" in fill
    assert "_adapter.commit_prepared" in fill

    for critical in (click, navigate, fill):
        assert "snapshot()" not in critical
        assert "_drain_observers" not in critical
        assert "BrowserAutomationAdministration" not in critical
