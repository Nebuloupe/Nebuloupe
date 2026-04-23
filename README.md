# Nebuloupe

Nebuloupe is a cloud misconfiguration security scanner for AWS, Azure, and GCP.
It supports:

- Live API-based posture scanning against deployed cloud resources
- Terraform IaC static analysis before deployment
- Combined IaC + API workflows with security gating
- A Streamlit dashboard with scan history and PDF export

## Why Nebuloupe

Nebuloupe is designed to help teams shift security left while still validating runtime reality:

- IaC scanning catches risky configs before deployment.
- API scanning catches drift, manual changes, and legacy risk in deployed environments.
- Unified findings output makes it easy to consume in pipelines and dashboards.

## Key Capabilities

- Multi-cloud scan scope: AWS, Azure, GCP
- Scan modes:
	- api: Live cloud scan only
	- iac: Terraform scan only
	- all: IaC scan first, then API scan (with IaC gating)
- Severity scoring model:
	- Critical = 10
	- High = 7
	- Medium = 4
	- Low = 1
- Optional CI gate using --fail-on to fail builds on selected severities
- JSON output artifacts in output/
- Scan history persistence for dashboard replay

## Project Structure

High-level structure:

- main.py: CLI entry point
- app.py: Streamlit dashboard entry point
- engine/: auth, scan orchestration, rule execution
- rules/: provider-specific and IaC rule plugins
- ui/: landing/dashboard/history pages, visuals, PDF export
- output/: generated scan artifacts
- validation/vulnerable_env/: sample vulnerable IaC environments

## Prerequisites

- Python 3.10+
- pip
- Cloud credentials for whichever provider you scan (for API mode)
- Terraform files (.tf / .tf.json) for IaC mode

## Installation

1. Clone repository
2. Create and activate a virtual environment
3. Install dependencies

Example:

```bash
python -m venv .venv
# Windows PowerShell
.venv\Scripts\Activate.ps1
# macOS/Linux
# source .venv/bin/activate

pip install -r requirements.txt
```

## Authentication Setup

Nebuloupe uses provider-native default credential chains.

### AWS

- CI/CD: set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY
- Local: run aws configure

### Azure

- CI/CD: set AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID
- Local: run az login

### GCP

- CI/CD: set GOOGLE_APPLICATION_CREDENTIALS to service account JSON path
- Local: run gcloud auth application-default login

## CLI Usage

Base command:

```bash
python main.py --cloud <aws|azure|gcp> [options]
```

### Common Examples

API scan only:

```bash
python main.py --cloud aws --mode api
```

IaC scan only:

```bash
python main.py --cloud aws --mode iac --tf-path ./terraform/
```

IaC then API:

```bash
python main.py --cloud aws --mode all --tf-path ./terraform/
```

Fail pipeline on High/Critical failures:

```bash
python main.py --cloud aws --tf-path ./infra/ --fail-on critical,high
```

Verbose debugging:

```bash
python main.py --cloud azure --mode api --verbose DEBUG
```

### CLI Flags

- --cloud (required): aws, azure, gcp
- --mode: api, iac, all (default: all)
- --tf-path: directory containing Terraform files
- --fail-on: comma-separated severities (critical,high,medium,low)
- --verbose: ERROR, INFO, DEBUG

## Streamlit Dashboard Usage

Start the dashboard:

```bash
streamlit run app.py
```

Dashboard supports:

- Cloud selection and scan trigger
- Findings summary and severity breakdown
- Filtering by severity/category
- Scan history replay from output/scan_history.json
- PDF export of reports

## Scan Modes Explained

### api

- Requires valid cloud credentials
- Runs live rules under rules/aws, rules/azure, or rules/gcp

### iac

- Does not require cloud credentials
- Scans Terraform files under the supplied --tf-path
- Loads rules from rules/iac/<provider>/ plus rules/iac/common/

### all

- Runs IaC first
- If Critical/High IaC failures exist, API phase is skipped
- Otherwise continues to API scan
- If both phases run, reports are merged into one result

## Output Artifacts

Nebuloupe writes outputs to output/:

- results.json: latest scan report
- scan_history.json: rolling scan history (default limit: 40)
- dummy_results.json: sample/dummy data (if present)

Report schema includes:

- scan_metadata
- summary
- findings[]

Findings are normalized for consistent fields:

- status is uppercased (PASS/FAIL)
- severity is canonicalized (Critical/High/Medium/Low)
- region defaults to global when missing
- cloud_provider is normalized

## Rule System

Rules are plugin-style Python modules discovered dynamically via filesystem walk and importlib.

To add a rule:

1. Add a new .py file in the correct rule folder.
2. Implement run_check(...) to return a list of finding dictionaries.
3. Ensure each finding includes expected schema fields (severity, status, check, resource_id, etc.).
4. Re-run scan; no central rule registry update is needed.

## CI/CD Integration

Use --fail-on to enforce security gates in pipelines:

```bash
python main.py --cloud gcp --mode all --tf-path ./infra --fail-on critical,high
```

Process exits non-zero if failing findings match selected severities.

## Limitations

- Detection-focused: Nebuloupe reports issues but does not auto-remediate infrastructure.
- Flat-file persistence (JSON) is simple but not optimized for high-concurrency writes.
- No centralized retry/backoff framework for all provider API throttling scenarios.

## Troubleshooting

- No credentials found:
	- Verify provider auth environment variables or CLI login state.
- --mode iac fails:
	- Ensure --tf-path is provided and contains .tf/.tf.json files.
- Empty/partial results:
	- Check output/results.json and CLI logs for scan_metadata.errors.

## Security Guidance

- Run with least-privilege read-only identities whenever possible.
- Protect generated reports, as they may contain sensitive asset metadata.
- Use approved/authorized environments and accounts only.

## License

No license file is currently included in this repository.
Add a LICENSE file if you plan to distribute or open source this project.
