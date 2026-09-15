# IncidentSight

> **Status: Concept scaffold**
>
> IncidentSight is an honest, deterministic starter for incident triage. It extracts
> explicit signals from logs and validates optional image metadata. It does **not**
> understand screenshot contents, establish root cause, call an LLM, or perform
> remediation.

IncidentSight demonstrates the boundary around a future multimodal workflow without
pretending that a local image-metadata parser is a vision model. The current baseline is
useful for API, validation, orchestration, testing, and safety-policy development.

## What works now

- FastAPI application on Python 3.12 with generated OpenAPI.
- `GET /health` readiness and capability disclosure.
- `POST /api/triage` multipart ingestion of incident metadata, logs, and an optional image.
- Deterministic extraction of log levels, exception-like identifiers, timeout wording,
  and contextualized HTTP status codes.
- Image validation plus detected format, width, height, and byte size only.
- Transparent severity heuristic.
- Separate observed evidence and explicitly marked hypotheses.
- Suggested read-only checks and an action plan where every step requires human approval.
- Stable validation and operational error envelopes.
- Replaceable analyzer/orchestrator protocols and a deliberately unimplemented
  `MultimodalProvider` port.

## Architecture

```text
multipart HTTP request
        |
        v
FastAPI boundary (validation, upload limits, error mapping)
        |
        v
BaselineTriageOrchestrator
   |                         |
   v                         v
RegexLogAnalyzer       PillowImageInspector
   |                         |
observed tokens          metadata only
        \                   /
         v                 v
 evidence + hypotheses + checks + approval-required plan

Future, opt-in path: reviewed MultimodalProvider adapter
                     (not implemented or configured)
```

The ports live in `src/incidentsight/interfaces.py`. The baseline orchestrator never calls
a provider. True screenshot interpretation requires a new provider adapter, explicit
configuration, credentials, user consent, and a data-handling review.

## Repository layout

```text
.
├── .github/workflows/ci.yml
├── examples/
├── src/incidentsight/
│   ├── analyzers/
│   ├── app.py
│   ├── interfaces.py
│   ├── models.py
│   └── triage.py
├── tests/
└── pyproject.toml
```

## Setup

Prerequisite: Python 3.12.

PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
python -m incidentsight
```

macOS/Linux:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
python -m incidentsight
```

The server listens on `http://127.0.0.1:8000`. Interactive API documentation is at
`/docs`; the generated schema is at `/openapi.json`.

Copy `.env.example` to `.env` only when overriding the documented upload limits.

## API

### Health

```console
curl http://127.0.0.1:8000/health
```

```json
{
  "status": "ok",
  "mode": "deterministic-baseline",
  "screenshot_interpretation": "not_configured"
}
```

### Triage

The endpoint consumes `multipart/form-data`:

- `metadata`: a JSON string matching `IncidentMetadata`.
- `log_text`: a non-empty plain-text excerpt, up to 500,000 characters.
- `image`: optional BMP, GIF, JPEG, PNG, or WebP upload.

From the repository root:

```console
curl --request POST http://127.0.0.1:8000/api/triage \
  --form "metadata=<examples/incident-metadata.json;type=application/json" \
  --form "log_text=<examples/sample-incident.log;type=text/plain"
```

On Windows PowerShell, invoke `curl.exe` to avoid the legacy `curl` alias. Add an image
without changing the contract:

```console
curl.exe --request POST http://127.0.0.1:8000/api/triage `
  --form "metadata=<examples/incident-metadata.json;type=application/json" `
  --form "log_text=<examples/sample-incident.log;type=text/plain" `
  --form "image=@C:\path\to\screenshot.png;type=image/png"
```

The response shape is:

```json
{
  "incident_id": "INC-2026-0915",
  "severity": "high",
  "summary": "Deterministic baseline assigned high severity ...",
  "evidence": [],
  "hypotheses": [
    {
      "statement": "An application code path may be failing.",
      "rationale": "The submitted logs contain exception-like identifiers ...",
      "confidence": "medium",
      "is_hypothesis": true
    }
  ],
  "suggested_checks": [],
  "action_plan": {
    "human_approval_required": true,
    "automation_executed": false,
    "steps": []
  },
  "limitations": []
}
```

`examples/triage-request.http` is a self-contained request for REST-client tooling.

## Deterministic severity policy

The policy is intentionally simple and auditable:

- `critical`: an explicit `CRITICAL` or `FATAL` level.
- `high`: corroborated 5xx plus an error/exception/timeout, at least two exceptions,
  or at least three explicit `ERROR` levels.
- `medium`: an error, exception, timeout, 5xx, or HTTP 429.
- `low`: a warning or another contextualized HTTP 4xx.
- `informational`: none of those signals.

Caller-reported impact and screenshot pixels do not change baseline severity. Teams should
replace this policy with reviewed service/SLA rules before operational use.

## Privacy and security

- Redact secrets, tokens, credentials, personal data, and unnecessary customer data before
  submission. Logs and screenshots commonly contain sensitive information.
- The application processes uploads in memory (or Starlette's temporary upload spool) and
  does not intentionally persist request contents.
- Image type is checked from decoded bytes, common raster formats are allowlisted, file
  bytes and pixel count are bounded, and Pillow's decompression-bomb warning is treated as
  an error.
- Returned filenames are reduced to a basename. Unexpected server errors are not returned
  to callers.
- This scaffold has no authentication, authorization, rate limiting, audit store, TLS
  termination, malware scanning, or tenant isolation. Add those controls at the service
  and reverse-proxy boundaries before any shared deployment.
- A future external multimodal provider would receive sensitive pixels and text. Do not
  add one without consent, retention/residency review, secret management, egress controls,
  provider attribution, and a non-provider fallback.
- Suggested checks are text only. No shell, cloud, ticketing, deployment, or remediation
  action is executed.

## Limitations

- Regex extraction can miss custom logging formats and can produce false positives.
- HTTP codes are recognized only in common status, HTTP response, and access-log contexts.
- Exception names provide no stack trace or causal proof.
- Image inspection reports format, dimensions, and bytes; there is no OCR, object
  detection, chart reading, UI interpretation, or visual reasoning.
- Severity has no topology, telemetry history, SLO, customer impact, or business context.
- Hypotheses are generated from signal categories and remain hypotheses.
- This is not a production incident-management system.

## Development and verification

```console
ruff format --check .
ruff check .
mypy src tests
python -m compileall -q src tests
pytest --cov=incidentsight --cov-report=term-missing
```

CI runs the same checks on Python 3.12 for pushes and pull requests.

## Roadmap

1. Add service-owned severity rules and versioned policy explanations.
2. Add authentication, authorization, request/audit identifiers, rate limiting, and
   production observability.
3. Add structured-log parsers and trace/metric references without ingesting excess data.
4. Define provider consent and privacy policy, then implement one opt-in
   `MultimodalProvider` adapter with attribution and evals.
5. Add prompt-injection defenses, model-output schemas, confidence calibration, and
   adversarial multimodal tests.
6. Integrate read-only incident context before considering separately approved action
   execution.

## License

MIT. See `LICENSE`.
