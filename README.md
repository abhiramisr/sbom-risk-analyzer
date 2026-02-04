# SBOM Risk Analyzer

An AI-powered Software Bill of Materials (SBOM) vulnerability analyzer built on AWS. Upload an SBOM, get prioritized vulnerabilities with contextual remediation guidance.

## Architecture
```
┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
│   S3 Input      │      │     Lambda      │      │   S3 Output     │
│   (SBOM upload) │────▶│   (Processor)    │────▶│   (Reports)    │
└─────────────────┘      └────────┬────────┘      └─────────────────┘
                                 │
                    ┌────────────┼────────────┐
                    ▼            ▼            ▼
              ┌─────────┐  ┌─────────┐  ┌─────────┐
              │   OSV   │  │  EPSS   │  │ Bedrock │
              │  (CVEs) │  │ (Prob.) │  │ (Claude)│
              └─────────┘  └─────────┘  └─────────┘
```

## Features

- **SBOM Parsing**: CycloneDX - JSON format support
- **Vulnerability Lookup**: OSV database integration for CVE discovery
- **EPSS Enrichment**: Exploit Prediction Scoring System for exploitation probability
- **CISA KEV Check**: Known Exploited Vulnerabilities catalog validation
- **AI Analysis**: Amazon Bedrock (Claude) for contextual prioritization and remediation
- **Guardrails**: Bedrock guardrails for safe LLM usage in security context
- **Encrypted Storage**: KMS encryption for data at rest

## Risk Scoring Logic

| Condition | Priority |
|-----------|----------|
| In CISA KEV | Critical |
| EPSS > 10% + CVSS ≥ 7.0 | Critical |
| CVSS ≥ 9.0 | Critical |
| EPSS > 10% | High |
| CVSS ≥ 7.0 | High |
| CVSS ≥ 4.0 | Medium |
| Default | Low |

## Project Structure
```
sbom-risk-analyzer/
├── lambda/
│   ├── handler.py           # Main Lambda handler
│   ├── vuln_lookup.py       # OSV vulnerability lookup
│   ├── enrichment.py        # EPSS + KEV enrichment
│   ├── bedrock_analyzer.py  # Bedrock LLM integration
│   └── test-sbom.json       # Sample SBOM for testing
├── terraform/
│   ├── main.tf              # Provider configuration
│   ├── s3.tf                # S3 buckets (input/output)
│   ├── kms.tf               # KMS encryption key
│   ├── iam.tf               # IAM roles and policies
│   ├── lambda.tf            # Lambda function
│   ├── variables.tf         # Input variables
│   └── outputs.tf           # Output values
└── README.md
```

## Prerequisites

- AWS Account with Bedrock access enabled
- Terraform >= 1.0
- Python 3.11+
- AWS CLI configured

## Deployment

1. **Clone the repository**
```bash
   git clone https://github.com/yourusername/sbom-risk-analyzer.git
   cd sbom-risk-analyzer
```

2. **Deploy infrastructure**
```bash
   cd terraform
   terraform init
   terraform plan -out=tfplan
   terraform apply tfplan
```

3. **Enable Bedrock model access**
   - Go to AWS Bedrock Console → Model access
   - Enable Claude 3 Sonnet

4. **Configure guardrail** (optional)
   - Create a Bedrock guardrail for security analysis
   - Update `GUARDRAIL_ID` in `lambda/bedrock_analyzer.py`

## Usage

1. **Generate an SBOM** (using syft, trivy, or similar)
```bash
   syft your-image:tag -o cyclonedx-json > sbom.json
```

2. **Upload to S3**
```bash
   aws s3 cp sbom.json s3://sbom-risk-analyzer-input-<account-id>/
```

3. **Retrieve the report**
```bash
   aws s3 cp s3://sbom-risk-analyzer-output-<account-id>/sbom-report.json .
```

## Sample Output
```json
{
  "summary": {
    "total_vulns": 9,
    "critical": 0,
    "high": 0,
    "in_kev": 0,
    "high_epss": 0
  },
  "components": [
    {
      "name": "lodash",
      "version": "4.17.15",
      "vulnerabilities": [
        {
          "cve_id": "CVE-2020-8203",
          "severity": "HIGH",
          "epss": 0.02087,
          "in_kev": false,
          "contextual_priority": "medium",
          "remediation": "Upgrade lodash to latest patched version",
          "rationale": "Mitigates Prototype Pollution vulnerability"
        }
      ]
    }
  ]
}
```

## Security Controls

| Control | Implementation |
|---------|----------------|
| Encryption at rest | KMS (SSE-KMS) |
| Encryption in transit | HTTPS/TLS |
| Access control | IAM least privilege |
| LLM safety | Bedrock guardrails |
| Input validation | Schema validation |
| Output sanitization | Allowed keys whitelist |

## Cost Estimate

| Service | Est. Monthly Cost |
|---------|-------------------|
| Lambda | ~$1 (1000 scans) |
| S3 | ~$1 |
| Bedrock | ~$5 (1000 scans) |
| KMS | ~$1 |
| **Total** | **~$8/month** |

## Future Enhancements

- [ ] SQS + DLQ for resilience
- [ ] SPDX format support
- [ ] Security Hub integration
- [ ] Slack/Teams notifications
- [ ] HTML report generation
- [ ] Zero-day impact analyzer — reverse lookup to find all applications affected by a newly disclosed CVE
- [ ] SBOM inventory database with DynamoDB
- [ ] Real-time alerts via SNS when KEV catalog updates match stored packages

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


## Author

Built by Abhirami Sasikala Rishikesavan as a security engineering portfolio project.