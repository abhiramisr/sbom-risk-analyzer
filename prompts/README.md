# Prompts

This folder contains prompt templates for Bedrock LLM analysis.

Currently, the prompt is embedded in `lambda/bedrock_analyzer.py` in the `build_analysis_prompt()` function.

## Known Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| **LLM Hallucination** | False CVEs or wrong remediation | CVE whitelist validation — only CVEs from input are accepted |
| **Prompt Injection** | Attacker crafts malicious SBOM to manipulate LLM | Input marked as untrusted, output schema enforced, allowed keys whitelisted |
| **Data Leakage** | Sensitive package names sent to external APIs | Only package name + version sent to OSV (public data); Bedrock stays in AWS account |
| **Guardrail Bypass** | LLM outputs harmful content | Bedrock guardrails + output validation + deterministic fallback |
| **Denial of Service** | Large SBOM overwhelms Lambda | Lambda timeout (2.5 min), bounded token output (1500), memory limit (256MB) |
| **Stale Threat Intel** | EPSS/KEV data outdated | KEV fetched fresh each invocation; EPSS updated daily by FIRST |
| **API Failures** | OSV/EPSS/Bedrock unavailable | Graceful degradation — deterministic scoring continues without LLM |
| **Credential Exposure** | AWS keys leaked | IAM roles only (no hardcoded keys), least-privilege policies |


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