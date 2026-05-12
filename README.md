# platform-cedar

Cedar policy sidecar for the TuxGrid platform attestation pipeline.

Evaluates Cedar policies against Jenkins build state and returns an authorization decision with reasons. Called by the attestation listener (`02-attest-build-listener.groovy`) before scheduling the cosign attestation job, and by the Token Service before issuing deployment credentials.

## Policies

| File | Action | Purpose |
|------|--------|---------|
| `policies/attest-gate.cedar` | `Attest` | Gates cosign attestation — all platform standards must pass |
| `policies/promote-gate.cedar` | `Promote` | Gates production promotion — all four attestation types required |
| `policies/audit-gap.cedar` | `AuditCompliance` | Periodic gap detection — finds pipelines that haven't attested recently |
| `policies/token-gate.cedar` | `IssueCredentials` | Gates Token Service credential issuance for non-k8s deployments |

Policies are mounted as a ConfigMap at runtime. A policy change is a `git push` — no image rebuild needed.

## Running locally

```bash
go build -o cedar-sidecar ./cmd/cedar-sidecar
CEDAR_POLICY_DIR=./policies ./cedar-sidecar
```

Test a deny (no tests ran):

```bash
curl -s -X POST http://localhost:8080/authorize \
  -H 'Content-Type: application/json' \
  -d '{
    "principal": "TuxGrid::Pipeline::\"teams/my-team/my-service\"",
    "action":    "TuxGrid::Action::\"Attest\"",
    "resource":  "TuxGrid::Image::\"sha256:abc123\"",
    "entities":  [],
    "context": {
      "testsRun": 0, "testsFailed": 0, "lineCoveragePct": 85,
      "coverageThreshold": 70, "hasArtifactsJson": true,
      "hasScanAttestation": true, "scanAgeSeconds": 0,
      "completedStages": ["Test","Build","Release"],
      "calledLibrarySteps": ["jenkins-library::microservicePipeline"]
    }
  }' | jq .
```

Test an allow (full passing build with entities):

```bash
curl -s -X POST http://localhost:8080/authorize \
  -H 'Content-Type: application/json' \
  -d '{
    "principal": "TuxGrid::Pipeline::\"teams/my-team/my-service\"",
    "action":    "TuxGrid::Action::\"Attest\"",
    "resource":  "TuxGrid::Image::\"sha256:abc123\"",
    "entities": [
      {"uid": {"type":"TuxGrid::Namespace","id":"development"}, "attrs": {"tier":"development"}, "parents": []},
      {"uid": {"type":"TuxGrid::Team","id":"my-team"}, "attrs": {"slug":"my-team","coverageThreshold":70}, "parents": [{"type":"TuxGrid::Namespace","id":"development"}]},
      {"uid": {"type":"TuxGrid::Pipeline","id":"teams/my-team/my-service"}, "attrs": {"jobPath":"teams/my-team/my-service","branch":"main","triggeredBySCM":true,"hasAuditId":true,"declaredBuild":true,"declaredTest":true}, "parents": [{"type":"TuxGrid::Team","id":"my-team"}]}
    ],
    "context": {
      "testsRun": 42, "testsFailed": 0, "lineCoveragePct": 85,
      "coverageThreshold": 70, "hasArtifactsJson": true,
      "hasScanAttestation": true, "scanAgeSeconds": 0,
      "completedStages": ["Test","Build","Release"],
      "calledLibrarySteps": ["jenkins-library::microservicePipeline"]
    }
  }' | jq .
```

## Running tests

```bash
go test ./cmd/cedar-sidecar/ -v
```

Tests cover all attest-gate deny conditions: no tests, failing tests, low coverage, missing artifacts, manual trigger, missing scan, missing library step, wrong stage order, missing audit ID, and the full passing allow case.
