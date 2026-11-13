"""Track foreground analysis tasks across application shutdown."""

from dataclasses import dataclass, field
from threading import Condition, Event
import time


@dataclass(eq=False)
class ForegroundTask:
    """A registered task and its cooperative cancellation signal."""

    cancel_event: Event = field(default_factory=Event)


class AnalysisTaskCoordinator:
    """Coordinate task registration, cancellation, completion and shutdown."""

    def __init__(self, max_active_tasks: int = 2) -> None:
        if max_active_tasks < 1:
            raise ValueError("max_active_tasks must be positive")
        self._condition = Condition()
        self._stopping = False
        self._max_active_tasks = max_active_tasks
        self._tasks: set[ForegroundTask] = set()

    def register(self) -> ForegroundTask | None:
        """Register work unless shutdown has already begun."""
        with self._condition:
            if self._stopping or len(self._tasks) >= self._max_active_tasks:
                return None
            task = ForegroundTask()
            self._tasks.add(task)
            return task

    def begin_completion(
        self,
        cancellation_event: Event,
        task: ForegroundTask | None = None,
    ) -> bool:
        """Win the completion/shutdown race before writing a terminal state."""
        with self._condition:
            if self._stopping or cancellation_event.is_set():
                return False
            if task is not None:
                if task not in self._tasks:
                    return False
            return True

    def request_shutdown(self) -> None:
        """Reject new work and cooperatively cancel every registered task."""
        with self._condition:
            self._stopping = True
            for task in self._tasks:
                task.cancel_event.set()
            self._condition.notify_all()

    def finish(self, task: ForegroundTask) -> None:
        with self._condition:
            self._tasks.discard(task)
            self._condition.notify_all()

    def wait_until_idle(self, timeout: float | None = None) -> bool:
        deadline = None if timeout is None else time.monotonic() + timeout
        with self._condition:
            while self._tasks:
                remaining = None if deadline is None else deadline - time.monotonic()
                if remaining is not None and remaining <= 0:
                    return False
                self._condition.wait(remaining)
        return True

    @property
    def stopping(self) -> bool:
        with self._condition:
            return self._stopping
