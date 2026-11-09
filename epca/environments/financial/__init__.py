from typing import Any

from epca.environments.financial.state import FinancialState


def __getattr__(name: str) -> Any:
    if name == "FinancialRuntime":
        from epca.environments.financial.environment import FinancialRuntime

        return FinancialRuntime
    raise AttributeError(name)


__all__ = ["FinancialRuntime", "FinancialState"]
