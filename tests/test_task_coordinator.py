import pytest

from app.task_coordinator import AnalysisTaskCoordinator


def test_foreground_task_admission_is_bounded_and_released_on_finish():
    coordinator = AnalysisTaskCoordinator(max_active_tasks=1)
    first = coordinator.register()

    assert first is not None
    assert coordinator.register() is None
    coordinator.finish(first)
    assert coordinator.register() is not None


def test_shutdown_rejects_new_tasks_and_cancels_registered_tasks():
    coordinator = AnalysisTaskCoordinator(max_active_tasks=1)
    task = coordinator.register()
    assert task is not None

    coordinator.request_shutdown()

    assert task.cancel_event.is_set()
    assert coordinator.register() is None
    assert coordinator.stopping


def test_foreground_capacity_must_be_positive():
    with pytest.raises(ValueError, match="must be positive"):
        AnalysisTaskCoordinator(max_active_tasks=0)
