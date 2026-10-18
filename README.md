# IBM Z Sentinel

Unified Mainframe Intelligence & Protection Platform — IBM Z Datathon 2026.

> **Synthetic demo only.** The application does not connect to z/OS, RACF, SMF, or production data. Approvals record human decisions; the application never executes remediation or system changes.

## Standard-library LinuxONE dashboard

`web_app.py` is the recommended LinuxONE dashboard. It uses Python's built-in HTTP server, HTML/CSS and existing Sentinel modules. It does not import Streamlit, PyArrow, pandas, or any third-party web framework. The existing `app.py` Streamlit interface is retained as a reference UI and is not needed by this dashboard. `requirements.txt` intentionally has no package requirements; the existing tests also use only the Python standard library.

The dashboard binds to `127.0.0.1` by default, renders a responsive IBM Z-inspired incident console, and uses the existing `SentinelStore` SQLite API for seeded snapshots and approval decisions. Same-seed refreshes upsert stable evidence and incident IDs without resetting approval decisions. Approval and rejection require an approver value, a confirmation checkbox, valid CSRF token/cookie and same-origin request. These actions only append the audit record; the execution state stays `Not executed`. Investigation is deterministic by default and works without Granite or any model endpoint; an explicit page link can try the optional local Granite adapter and falls back to deterministic findings.

### LinuxONE launch and browser access

On Ubuntu 24.04 / s390x, Python 3.12 and SQLite support are expected from the system Python build. From the project directory:

```bash
python3.12 --version
python3.12 -m unittest discover -s tests -v
export SENTINEL_DB_PATH="$PWD/data/sentinel.db"
python3.12 web_app.py --host 127.0.0.1 --port 8501
```

The first dashboard request initializes the local SQLite schema and seeds the synthetic demo if there are no incidents. On your local computer, create an SSH tunnel to the VM:

```bash
ssh -i /path/to/your-private-key.pem -N -L 8501:127.0.0.1:8501 <vm-user>@<linuxone-vm-address>
```

Keep that terminal open and browse to `http://127.0.0.1:8501/` on your computer. The private key stays on your computer. The server remains loopback-bound on the VM; do not pass `--host 0.0.0.0` unless you deliberately intend to expose it and have configured network controls.

### Troubleshooting

- If `python3.12` is not found, check the VM's installed interpreter with `python3 --version`; run the tests and app with that Python 3.12 executable.
- If port 8501 is occupied, choose another local port, for example `--port 8510`, and use the same port on both sides of the SSH `-L 8510:127.0.0.1:8510` forward.
- If the page cannot be reached, confirm the server is running, the SSH tunnel is open, and the browser URL uses the local forwarded port. No public inbound port is needed.
- If the synthetic incident does not appear, use **Load / refresh seeded demo**. Reusing the same seed does not duplicate records or clear approval history.
- Database errors can be isolated by setting `SENTINEL_DB_PATH` to a writable location. Back up the SQLite file with the server stopped.
- The dashboard does not need `pip install`, Streamlit, PyArrow, pandas, a model download, or an external database.

## Implemented features

- `web_app.py` is the loopback-first standard-library HTTP dashboard and integrates the existing event generator, explainable risk scorer, time-window correlation, evidence-cited investigation, remediation recommendations, and SQLite store. `app.py` remains the optional legacy Streamlit reference UI.
- `sentinel/evidence.py` includes the synthetic payroll-close path and a payment-settlement path: an unapproved COBOL program change, a restricted-data baseline and access events, an RC=0 batch job with expected/processed records and control totals, an output dataset, and a downstream settlement consumer. The payment example expects 100,000 records and processes 99,000. All records, detector findings, IDs, identities, references, and datasets are synthetic.
- `sentinel/detection.py` derives access findings by comparing sensitive reads with an approved-actor/frequency baseline, and detects record-count or control-total shortfalls even when the job return code is zero. These are detector outputs, not pre-labeled source anomaly events.
- `sentinel/correlation.py` resolves explicit evidence-ID dependency links (program to batch job to output dataset to settlement consumer, and detector findings) within the configured time window. Actor/resource fallback links use an explicit cross-signal pair allowlist; arbitrary shared attributes do not merge events. Incidents carry business criticality/process labels.
- `sentinel/investigation.py` produces deterministic program-change, access-baseline, and batch-integrity findings with citations to detector and source event IDs. For payment settlement it describes the change/access as hypotheses and possible downstream impact without asserting causation or a missed payment.
- `sentinel/remediation.py` adds scenario-specific review and downstream-output/settlement hold recommendations. A hold is only recorded as a human decision; no dataset, job, or settlement process is changed.
- The dashboard displays incident severity and risk, actors/resources, correlated evidence IDs, cited investigation conclusions, event timeline, recommendations, approval status, and decision audit history.
- The first visit seeds a synthetic snapshot. **Load / refresh seeded demo** explicitly regenerates and upserts that seed. Stable event and incident IDs prevent duplicate records, and refresh retains prior approval decisions.
- `sentinel/storage.py` uses Python's built-in SQLite module. Its schema stores normalized evidence, incidents, incident/evidence links, recommendations, and append-only approval history. Initialization is repeatable, foreign keys are enabled, write operations are transactional, and a database from a newer unsupported schema version is rejected.
- Approving or rejecting requires an approver name/ID, a confirmation checkbox, and a separate confirmation button. Each decision records timestamp, approver and outcome. Execution remains `Not executed`.
- Deterministic investigation runs without an LLM. Optional local Granite inference uses an Ollama-compatible endpoint and falls back to deterministic conclusions when unavailable. Model citations are checked against IDs from the selected incident.
- `tests/` uses standard-library `unittest`, including HTTP dashboard, CSRF, approval gating, and persistence coverage; tests need no Streamlit import.

The seeded payroll-close case remains available for backward compatibility. The payment-settlement case is marked business critical and demonstrates: an unapproved COBOL program change; restricted payment-data access by an actor outside the approved baseline; a batch job reporting RC=0 while processing 99,000 of 100,000 expected records; derived count/control-total discrepancy findings; and explicit program-to-job-to-output-dataset-to-settlement-consumer dependencies. All records remain synthetic and do not represent real transactions or live integrations.

The SQLite file defaults to `data/sentinel.db`. Set `SENTINEL_DB_PATH` to choose another location. Back up this file while the dashboard is stopped. A single local SQLite file is intended for a demo or one application instance, not concurrent multi-host operation.

## Windows setup

From the project directory in PowerShell:

```powershell
python --version
python -m unittest discover -s tests -v
python web_app.py --host 127.0.0.1 --port 8501
```

Open `http://127.0.0.1:8501/` on the same computer.

### Optional legacy Streamlit reference

`app.py` remains available as the original reference interface and is not used by `web_app.py`. The standard-library dashboard and tests require no package installation. To run the optional reference app separately, install a compatible Streamlit release in a virtual environment; its transitive dependencies, including PyArrow, have not been verified on LinuxONE s390x.

## Optional local Granite

The deterministic path is the default and needs no model download. The standard-library `web_app.py` always uses this deterministic path. For the optional legacy Streamlit interface (`app.py`), a local Ollama-compatible service with Granite can be enabled by setting these variables and turning on **Try local Granite model** in its sidebar:

```bash
export SENTINEL_GRANITE_URL=http://127.0.0.1:11434/api/generate
export SENTINEL_GRANITE_MODEL=granite3.3:2b
```

The adapter is compatible with the Ollama `/api/generate` response format. Other serving APIs need a small adapter. The model and endpoint were not included or tested here. Keep credentials out of source control.

## Known limitations

- Evidence and access baselines are synthetic. The risk model is an illustrative heuristic, not a calibrated production detector.
- Program/access/batch dependencies are generated for this scenario; they do not represent live z/OS program libraries, RACF profiles, SMF records, scheduler feeds, or business data.
- Access detection uses a small synthetic approved-actor and read-frequency baseline. It is not a production identity analytics or adaptive anomaly model.
- SQLite history is local to one VM. No backup automation, multi-user authentication, or remote audit sink is included.
- Approval history records the entered operator ID and UI confirmation; it is not identity proof or an authorization system. Decisions do not execute actions.
- Refreshing the same seed updates its stable event records and current incident view while preserving decisions; it does not maintain a separate immutable event snapshot for every refresh.
- The optional model's citations are validated, but citations alone cannot guarantee factual model output.
- The optional legacy Streamlit/PyArrow interface is not required for LinuxONE and its dependency installation on s390x is unverified. The new standard-library HTTP dashboard has not yet been runtime-validated on the target VM.
