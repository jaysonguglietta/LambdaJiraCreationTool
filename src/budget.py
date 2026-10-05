from __future__ import annotations

import time


class BudgetExhausted(RuntimeError):
    """Checkpoint and continue instead of starting work that cannot safely finish."""


class Budget:
    def __init__(self, seconds: float = 240, *, clock=time.monotonic):
        self.clock = clock
        self.deadline = clock() + seconds

    def remaining(self) -> float:
        return max(0.0, self.deadline - self.clock())

    def require(self, seconds: float = 35) -> None:
        if self.remaining() < seconds:
            raise BudgetExhausted("Invocation budget exhausted; work is checkpointed")
