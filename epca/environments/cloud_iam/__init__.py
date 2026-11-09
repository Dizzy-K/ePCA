from typing import Any

from epca.environments.cloud_iam.state import CloudIAMState


def __getattr__(name: str) -> Any:
    if name == "CloudIAMRuntime":
        from epca.environments.cloud_iam.environment import CloudIAMRuntime

        return CloudIAMRuntime
    raise AttributeError(name)


__all__ = ["CloudIAMRuntime", "CloudIAMState"]
