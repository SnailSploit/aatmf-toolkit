# AATMF Red Teaming Toolkit

**Adversarial AI Threat Modeling Framework** — A Python CLI tool for testing LLM safety guardrails.

## Overview

The AATMF Toolkit sends adversarial prompts ("probes") to target LLMs and evaluates whether the model blocked or complied with harmful requests. It includes four integrated tools:

1. **Red Card Runner** — Executes probe suites against a target model and scores pass/fail
2. **Fingerprinter** — Profiles a model's defense behavior to identify safety system types
3. **Decay Monitor** — Tracks model safety over time, detecting regressions after updates
4. **Attack Chain Simulator** — Plans multi-step attack sequences combining techniques

## Installation

```bash
pip install -e .
```

## Quick Start

```bash
# Run a Red Card against GPT-4o
aatmf run examples/example_card.yaml --target openai:gpt-4o

# Dry run (no API calls)
aatmf run examples/example_card.yaml --target openai:gpt-4o --dry-run

# Fingerprint a model's defenses
aatmf fingerprint --target openai:gpt-4o

# Check for safety regressions
aatmf decay --cards ./cards --target openai:gpt-4o

# Plan attack chains
aatmf chain --profile profile.json --max-steps 4 --top-k 5

# Parse FIXED.md files into Red Card YAMLs
aatmf load ./source-tactics --output ./cards
```

## Environment Variables

```
OPENAI_API_KEY       — Required for OpenAI targets and default judge
ANTHROPIC_API_KEY    — Required for Anthropic targets
AATMF_EVAL_TIER     — Default: 2
AATMF_JUDGE_MODEL   — Default: gpt-4o
AATMF_CONCURRENCY   — Default: 5
AATMF_MAX_BUDGET    — Default: 50.0
AATMF_LOG_LEVEL     — Default: INFO
```

## License

MIT
