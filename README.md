# NCCU ACVP Server — Research Fork

> **Research repository**
>
> This repository is a research fork of
> [William901105/NCCU-ACVP-Server](https://github.com/William901105/NCCU-ACVP-Server)
> and is maintained for master's thesis research on ACVP-based validation of
> post-quantum cryptographic implementations.
>
> The research baseline is derived from the upstream `strict` workflow and
> preserves its strict ACVP architecture, PostgreSQL storage, access-token
> workflow, and NIST GenVal execution backend.
>
> Research-specific changes currently include:
>
> - Restored printable **Validation Summary Report**
> - Restored printable **Diagnostic Report**
> - Detailed failed test-group and test-case diagnostics
> - IUT response SHA-256 and implementation metadata in diagnostic reports
> - Improved print pagination for validation reports
>
> Future thesis-oriented experiments, evaluation tooling, and research
> extensions will be developed in this repository.
>
> **Important:** This system is a research and validation platform. It is not
> the official NIST ACVP service and does not issue NIST/CAVP validation
> certificates.

---

# NCCU ACVP Server

NCCU ACVP Server exposes a strict-only ACVP v1 workflow for FIPS 203 / ML-KEM
and FIPS 204 / ML-DSA.

## Algorithm-neutral Core

The strict runtime is assembled from algorithm-neutral protocol services and
an injected algorithm module registry. Each module owns its immutable
descriptor, schema validation, capability negotiation, NIST registration
mapping, and NIST validation normalization. The protocol layer dispatches by
`AlgorithmIdentity` and does not import concrete algorithm packages.

`GET /acvp/v1/algorithms` is generated entirely from registered descriptors.
ML-DSA and ML-KEM are registered once during application startup with provider
IDs `nist-ml-dsa-fips204` and `nist-ml-kem-fips203`. The backend can dispatch
registration, prompt, and response schemas and NIST registration mapping for
both modules. NIST GenVal remains the only execution backend.

## Strict ACVP Policy

- Every new `/acvp/v1` test session is a registration-container session.
- `POST /acvp/v1/testSessions` accepts `algorithms`, `label`,
  `autoGenerateVectorSets`, `campaignSeed`, `testsPerGroup`, `isSample`,
  `expiresInSeconds`, and `metadata`.
- Prompt-based session creation is disabled. `prompt` returns
  `STRICT_REGISTRATION_REQUIRED`; `autoGenerateExpectedResults` returns
  `AUTO_EXPECTED_RESULTS_NOT_SUPPORTED`.
- All generation and validation use NIST ACVP-Server GenVal. There is no local
  generator or local validation fallback reachable through `/acvp/v1`.
- Server responses identify `workflowPolicy: strict` and
  `executionBackend: nist-genval`.
- Clients cannot set `workflowPolicy` or `executionBackend`. There are no
  workflow or generation profile controls in the API or frontend.
- `isSample: true` permits the expected-results endpoint. Non-sample expected
  results remain server-side and return `EXPECTED_RESULTS_NOT_AVAILABLE`.

Legacy records created by earlier local workflows remain readable. Any attempt
to generate, submit, or validate such a record returns
`LEGACY_LOCAL_SESSION_NOT_SUPPORTED`; records are not converted.

The local oracle, validator, expected-result generator, import pipeline, and
demo endpoints have been removed. Production runtime code has no local
generation or validation fallback.

`IUT-tests/mldsa-native/` (ML-DSA / FIPS 204) and `IUT-tests/mlkem-native/`
(ML-KEM / FIPS 203) are external implementation-under-test harnesses; they are
not server oracles. `mlkem-native` derives ACVP responses with the vendored
GiacomoPope/kyber-py implementation in `third_party/kyber-py/` (provenance in
`third_party/kyber-py/KYBER_SOURCE.md`). The repository sample and NIST fixtures
are test inputs only and are not exposed by production endpoints.

## API Workflow

```text
POST /acvp/v1/accessTokens
POST /acvp/v1/testSessions
GET  /acvp/v1/testSessions/{sessionId}/vectorSets/{vsId}
POST /acvp/v1/testSessions/{sessionId}/vectorSets/{vsId}/results
GET  /acvp/v1/testSessions/{sessionId}/vectorSets/{vsId}/results
GET  /acvp/v1/testSessions/{sessionId}/results
PUT  /acvp/v1/testSessions/{sessionId}
GET  /acvp/v1/requests/{requestId}
GET  /acvp/v1/testSessions/{sessionId}/reports/pdf
```

`POST /acvp/v1/accessTokens` requires no account registration or login. It
returns an opaque Bearer token that expires after 30 minutes by default. All
other `/acvp/v1` requests require `Authorization: Bearer <accessToken>`. The
frontend's `Get New Access Token` button stores the token in browser
`localStorage` and adds the header automatically. PostgreSQL stores only the
token's SHA-256 digest and expiry metadata; missing, invalid, or expired tokens
return HTTP 401.

The explicit generation endpoint remains available for a session created with
`autoGenerateVectorSets: false`:

```text
POST /acvp/v1/testSessions/{sessionId}/vectorSets/generate
```

Test-session registration and certification use a two-object ACVP
`acvVersion: 1.0` envelope. Bare registration objects remain a deprecated local
compatibility input. Numeric `vsId` is the canonical public vector identity;
internal database UUIDs are not emitted. Certification creates a persistent
request resource in `initial` status because this server is not connected to an
external validation authority. It does not issue a certificate or validation
ID. Obsolete workflow-selection or generation-selection query parameters
return HTTP 400.

After every vector set in a session has completed validation, the authenticated
PDF report endpoint returns one downloadable test-session summary. It contains
the session metadata, certification request state when present, algorithm and
vector-set metadata, and pass/fail counts. Raw prompt, IUT response, validation,
internal projection, and expected-results JSON are not rendered in the PDF.
The report is local validation evidence and is explicitly not a NIST/CAVP
certificate.

## NIST GenVal Adapter

The NIST ACVP-Server source is vendored in `third_party/nist-acvp-server/`.
Provenance is in `third_party/nist-acvp-server/NIST_SOURCE.md`.

```bash
./scripts/nist/build_nist_genval.sh
./scripts/nist/start_orleans.sh
```

The NIST source is already vendored. Only maintainers refreshing that source
from a local checkout at the exact pinned commit should run:

```bash
./scripts/nist/copy_nist_genval.sh /path/to/ACVP-Server
```

Runtime settings:

- `ACVP_GENVAL_RUNNER_DLL`
- `ACVP_GENVAL_ARTIFACT_ROOT`
- `ACVP_GENVAL_TIMEOUT_SECONDS`

If the runner is unavailable, generation or validation returns a NIST GenVal
error; the server does not use a Python fallback.

NIST's generated prompt, expected results, and internal projection are stored
as artifacts. The internal projection is never returned by the public API;
expected results are returned only for sample vector sets.

## Development

PostgreSQL is the only runtime database. Create separate application and test
databases, then configure their URLs:

```bash
export DATABASE_URL='postgresql://acvp_app:<password>@127.0.0.1:5432/acvp'
export ACVP_TEST_DATABASE_URL='postgresql://acvp_test_user:<password>@127.0.0.1:5432/acvp_test'
```

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pytest -q
```

```bash
cd frontend
npm ci
npm run build
npm run dev
```

The frontend runs at `http://127.0.0.1:5173`; the backend normally runs with:

```bash
cd backend
uvicorn app.main:app --reload --port 8000
```

## Single-host Docker deployment

The supported container layout uses three Docker Compose services: an Nginx
frontend, an ACVP engine containing FastAPI plus the local NIST GenVal/Orleans
runtime, and PostgreSQL 16. PostgreSQL data and NIST GenVal artifacts are kept
in separate persistent volumes. Only the frontend port is published.

See [`DEPLOYMENT.md`](DEPLOYMENT.md) for build, startup, backup, database, and
offline-delivery instructions. ML-KEM manual IUT acceptance is documented in
[`docs/mlkem-iut-testing.md`](docs/mlkem-iut-testing.md).

## Scope

The backend registry supports ML-DSA `keyGen`, `sigGen`, and `sigVer` for
FIPS204, ML-DSA `sigGen` for FIPS204-tr1, and ML-KEM `keyGen` and `encapDecap`
for FIPS203. The algorithms endpoint lists the immutable descriptors, and each
module provides strict registration, prompt, response, mapper, and NIST
validation-normalization contracts. ML-KEM FIPS203-tr1 is not currently
registered.

The frontend supports both FIPS 204 and FIPS 203 registration workflows. The
ML-KEM IUT harness in `IUT-tests/mlkem-native/` is verified against the
repository NIST FIPS 203 fixtures. Mixed ML-DSA/ML-KEM sessions have not been
formally supported or accepted.

Current guides and historical Stage/audit records are classified in
[`docs/README.md`](docs/README.md). Historical records describe their pinned
stage only and must not be used as current startup or API instructions.
