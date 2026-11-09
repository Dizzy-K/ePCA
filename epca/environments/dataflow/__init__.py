from typing import Any

from epca.environments.dataflow.state import DataFlowState


def __getattr__(name: str) -> Any:
    if name == "DataFlowRuntime":
        from epca.environments.dataflow.environment import DataFlowRuntime

        return DataFlowRuntime
    raise AttributeError(name)


__all__ = ["DataFlowRuntime", "DataFlowState"]
