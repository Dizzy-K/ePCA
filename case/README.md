# Case Study: Enterprise BI Agent Sandbox

This directory packages the Enterprise BI Agent Sandbox scenario into the publishable `github/` artifact tree.

Included files:

- `run_case.py`: live runner that binds an LLM to the sandbox tools and logs the trajectory.
- `guardrail.py`: Z3-based EPCA guardrail used to approve or block each tool invocation.
- `tools.py`: tool schemas, payload validation, and state transition logic.
- `logs/apt_trajectory_20260331T071314.130993Z.log`: one representative packaged run log.

Run from the `github/` directory:

```bash
python case/run_case.py --max-turns 16
```

The runner writes new logs into `case/logs/`.
