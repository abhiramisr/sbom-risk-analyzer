# Prompts

This folder contains prompt templates for Bedrock LLM analysis.

Currently, the prompt is embedded in `lambda/bedrock_analyzer.py` in the `build_analysis_prompt()` function.


## Future Enhancement

Move prompts to external files for:
- Version control of prompt iterations
- A/B testing different prompt strategies
- Easier tuning without code changes

## Prompt Design Principles

1. **Constrained output** — JSON schema enforcement
2. **Input sanitization** — Mark untrusted data clearly
3. **Anti-injection** — Instruct model to ignore embedded instructions
4. **Validation** — Whitelist allowed keys and values
5. **Fallback** — Deterministic scoring if LLM fails