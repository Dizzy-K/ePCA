# Working with this artifact

Start with README.md and REPRODUCIBILITY.md. The current entry point is `python scripts/reproduce_paper.py`, which aggregates existing records offline.

Keep archived inputs and outputs unchanged. Put new outputs under build/ or a new results/local_* directory. Keep the earlier policy-gap cohort separate from the cumulative-approval cohort. No remote calls are needed for artifact inspection or the local/mocked test suite.

Live model experiments require an explicit user request and runtime credentials. Never place credentials in source, configuration, results, or reports. Preserve the evidence boundaries in OPEN_SCIENCE.md.

The original exp/ and case/ directories are historical artifacts. Their original guides remain in Git history.
