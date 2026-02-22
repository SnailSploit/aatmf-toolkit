# Contributing to AATMF Toolkit

Thanks for your interest in contributing to the AATMF Red Teaming Toolkit.

## Development Setup

```bash
git clone https://github.com/snailsploit/aatmf-toolkit.git
cd aatmf-toolkit
pip install -e ".[dev]"
pytest -v
```

## Adding Red Cards

Red Cards are YAML test suites. See `examples/` for the format. Each card targets one AATMF technique and contains multiple probes.

Key rules:

- Every card needs an `id`, `aatmf_tactic`, `aatmf_technique`, and at least one probe
- Probes must have `expect.should_block` and ideally `must_not_contain` terms
- Do NOT include real harmful payloads — test the pattern, not the content

## Adding Defense Signatures

Fingerprint signatures live in `data/signatures.json`. To add a new defense system profile, run the fingerprinter against it and compare the behavioral profile to known signatures.

## Running Tests

```bash
pytest -v                          # all tests
pytest tests/test_evaluator.py -v  # specific module
ruff check aatmf/                  # lint
ruff format aatmf/                 # format
```

## Code Style

- Python 3.11+, Pydantic v2 models
- async/await for all LLM calls
- structlog for logging
- Type hints on all public functions

## Submitting

1. Fork the repo
2. Create a feature branch
3. Add tests for new functionality
4. Ensure `pytest -v` passes and `ruff check` is clean
5. Open a PR with a clear description
