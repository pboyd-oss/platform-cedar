# platform-cedar

## Purpose

The cedar sidecar is the policy-as-code authorization engine for the TuxGrid build-integrity platform. It is a stateless Go HTTP server that evaluates Cedar policy files against structured build context, returning ALLOW or DENY with human-readable reasons. It sits at the center of the capability-gate chain: the attest-coordinator, token-service, and release pipeline all call `POST /authorize` before granting any capability (image signing, AWS credentials, production promotion), so every gate in the chain is reducible to a Cedar policy change with no image rebuild required.

Cedar policy sidecar for the TuxGrid platform attestation pipeline. A stateless Go HTTP server that loads `.cedar` policy files from a directory at startup and evaluates authorization requests via `POST /authorize`. No database. Policies are mounted as a ConfigMap, so a policy change is a `git push` with no image rebuild.

## What it does

Evaluates Cedar policies against structured context and entities, returning ALLOW or DENY with human-readable reason strings. Called by three callers:

| Caller | Action | When |
|--------|--------|------|
| `platform-attest-coordinator` | `Attest` | Before scheduling the cosign attest job |
| `PlatformReleasePipeline` | `Promote` | Before promoting an image to production |
| `PlatformAuditCompliancePipeline` | `AuditCompliance` | Daily cron gap detection |
| `platform-token-service` | `IssueCredentials` | Before issuing STS credentials |

## Key files

| File | Purpose |
|------|---------|
| `cmd/cedar-sidecar/main.go` | HTTP server; loads policies; handles `/authorize` |
| `cmd/cedar-sidecar/main_test.go` | Integration tests using real policy files |
| `cmd/cedar-sidecar/policies_test.go` | Policy-level unit tests |
| `policies/attest-gate.cedar` | Attest action -- 16 forbid rules covering tests, coverage, library steps, audit anomalies, pinned SHAs, etc. |
| `policies/promote-gate.cedar` | Promote action -- requires all 6 attestation types for production; scan age < 24h |
| `policies/audit-gap.cedar` | AuditCompliance action -- fires when pipeline has not attested in 7 days or has never produced a scan/v1 attestation |
| `policies/token-gate.cedar` | IssueCredentials action -- requires `scanAttestationVerified`; production requires all 6 attestation types |
| `schema/tuxgrid.cedarschema` | Entity types and action context shapes for all four actions |
| `k8s/deployment.yaml` | Deployment (2 replicas, `platform-cedar-sidecar`, port 80) |
| `kustomization.yaml` | ArgoCD-managed ConfigMap generator (policy files only) |
| `k8s/kustomization.yaml` | Jenkins-managed workload resources |

## API endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/healthz` | Returns 200 |
| `POST` | `/authorize` | Evaluate Cedar policy; returns `{"decision":"ALLOW|DENY","reasons":[...]}` |

No authentication on any endpoint -- access controlled by Cilium NetworkPolicy.

**K8s service:** `platform-cedar-sidecar` in namespace `platform`, port 80.
**Internal URL:** `http://platform-cedar-sidecar.platform.svc.cluster.local:80`
**External URL:** `https://cedar.tuxgrid.com`

## Authorization request shape

```json
{
  "principal": "TuxGrid::Pipeline::\"teams/my-team/my-svc\"",
  "action":    "TuxGrid::Action::\"Attest\"",
  "resource":  "TuxGrid::Image::\"sha256:abc123\"",
  "entities":  [...],
  "context":   {...}
}
```

The `entities` array is critical for `Attest` -- Cedar entity attributes (`hasAuditId`, `triggeredBySCM`, `declaredBuild`, `declaredTest`) are enforced only when the entity object is present in the request. The `platform-attest-coordinator` always builds entities via `buildCedarEntities()` in `coordinator/cedar.go`.

## Attest action -- required context fields

All fields from `schema/tuxgrid.cedarschema`:

| Field | Type | Description |
|-------|------|-------------|
| `testsRun` | Long | JUnit test count; 0 -> DENY |
| `testsFailed` | Long | Failing tests; >0 -> DENY |
| `lineCoveragePct` | Long | Line coverage percentage |
| `coverageThreshold` | Long | Team-configured threshold; coverage < threshold -> DENY |
| `hasArtifactsJson` | Bool | artifacts.json archived; false -> DENY |
| `hasScanAttestation` | Bool | scan/v1 attestation present |
| `scanAgeSeconds` | Long | Age of scan in seconds |
| `completedStages` | Set<String> | Stage names that completed with SUCCESS |
| `calledLibrarySteps` | Set<String> | Library steps called, e.g. `"jenkins-library::microservicePipeline"` |
| `auditAnomalyCount` | Long | Undeclared execs from audit service; >0 -> DENY |
| `auditUnexpectedNetworkCount` | Long | Direct external TCP connections; >0 -> DENY |
| `hasUnpinnedLibraries` | Bool | Any library loaded at branch name (not SHA); true -> DENY |

**Required entity attributes on `TuxGrid::Pipeline`:**
- `hasAuditId` (Bool) -- false -> DENY
- `triggeredBySCM` (Bool) -- false -> DENY
- `declaredBuild` (Bool) -- used to gate Build stage checks
- `declaredTest` (Bool) -- used to gate Test stage checks

## AuditCompliance -- required context fields (known issue)

The `PlatformAuditCompliancePipeline` currently calls Cedar with no context, which causes DENY with no reasons. Required fields:

| Field | Type | Description |
|-------|------|-------------|
| `lastAttestationAgeSeconds` | Long | Seconds since last successful attestation; >604800 (7 days) -> DENY |
| `attestationTypes` | Set<String> | Attestation types present on latest image |

Until the pipeline is fixed, every AuditCompliance call will DENY. This does not affect build attestation or credential issuance.

## How to run locally

```bash
cd services/platform-cedar
go build -o cedar-sidecar ./cmd/cedar-sidecar
CEDAR_POLICY_DIR=./policies ./cedar-sidecar
# Listens on :8080
```

Test a DENY (no tests):
```bash
curl -s -X POST http://localhost:8080/authorize \
  -H 'Content-Type: application/json' \
  -d '{
    "principal": "TuxGrid::Pipeline::\"teams/my-team/my-svc\"",
    "action":    "TuxGrid::Action::\"Attest\"",
    "resource":  "TuxGrid::Image::\"sha256:abc123\"",
    "entities":  [],
    "context": {
      "testsRun": 0, "testsFailed": 0, "lineCoveragePct": 85,
      "coverageThreshold": 70, "hasArtifactsJson": true,
      "hasScanAttestation": true, "scanAgeSeconds": 0,
      "completedStages": ["Test","Build"],
      "calledLibrarySteps": ["jenkins-library::microservicePipeline"],
      "auditAnomalyCount": 0, "auditUnexpectedNetworkCount": 0,
      "hasUnpinnedLibraries": false
    }
  }' | jq .
```

Test an ALLOW (full passing build with entities):
```bash
curl -s -X POST http://localhost:8080/authorize \
  -H 'Content-Type: application/json' \
  -d '{
    "principal": "TuxGrid::Pipeline::\"teams/my-team/my-svc\"",
    "action":    "TuxGrid::Action::\"Attest\"",
    "resource":  "TuxGrid::Image::\"sha256:abc123\"",
    "entities": [
      {"uid": {"type":"TuxGrid::Namespace","id":"development"}, "attrs": {"tier":"development"}, "parents": []},
      {"uid": {"type":"TuxGrid::Team","id":"my-team"}, "attrs": {"slug":"my-team","coverageThreshold":70}, "parents": [{"type":"TuxGrid::Namespace","id":"development"}]},
      {"uid": {"type":"TuxGrid::Pipeline","id":"teams/my-team/my-svc"}, "attrs": {"jobPath":"teams/my-team/my-svc","branch":"main","triggeredBySCM":true,"hasAuditId":true,"declaredBuild":true,"declaredTest":true}, "parents": [{"type":"TuxGrid::Team","id":"my-team"}]}
    ],
    "context": {
      "testsRun": 42, "testsFailed": 0, "lineCoveragePct": 85,
      "coverageThreshold": 70, "hasArtifactsJson": true,
      "hasScanAttestation": true, "scanAgeSeconds": 0,
      "completedStages": ["Test","Build"],
      "calledLibrarySteps": ["jenkins-library::microservicePipeline","jenkins-library::runTests","jenkins-library::buildApp"],
      "auditAnomalyCount": 0, "auditUnexpectedNetworkCount": 0,
      "hasUnpinnedLibraries": false
    }
  }' | jq .
```

## Test commands

```bash
cd services/platform-cedar
go test ./cmd/cedar-sidecar/ -v
```

Tests cover all 16 attest-gate deny conditions plus the full passing allow case.

## Deployment

Policies and the workload are deployed separately:

| What | Managed by | How to update |
|------|-----------|---------------|
| `cedar-policies` ConfigMap | ArgoCD | Push changes to `policies/` on `main`; ArgoCD syncs on next reconcile |
| Deployment / Service / HTTPRoute | Jenkins release pipeline | Push to `main`; Jenkins builds and promotes |

### Local deploy (bypassing Jenkins)

```bash
kubectl get secret cosign-key -n jenkins -o jsonpath='{.data.cosign\.key}' | base64 -d > /tmp/cosign.key

docker build --platform linux/amd64 \
  -t harbor.tuxgrid.com/platform/cedar-sidecar:latest .

docker push harbor.tuxgrid.com/platform/cedar-sidecar:latest

DIGEST=sha256:<from push>
COSIGN_PASSWORD="" cosign sign \
  --key /tmp/cosign.key \
  --tlog-upload=false --use-signing-config=false --new-bundle-format=false \
  --yes harbor.tuxgrid.com/platform/cedar-sidecar@${DIGEST}

kubectl set image deployment/platform-cedar-sidecar -n platform \
  cedar-sidecar=harbor.tuxgrid.com/platform/cedar-sidecar@${DIGEST}
kubectl rollout status deployment/platform-cedar-sidecar -n platform
```

## Known issues and TODOs

- **AuditCompliance DENY with no reasons**: `PlatformAuditCompliancePipeline` does not pass required context fields (`lastAttestationAgeSeconds`, `attestationTypes`). Every compliance check is a DENY until fixed.
- **No hot-reload**: policy changes require a ConfigMap update and a pod restart (or `rollout restart`) to take effect. The service reads policies once at startup.
- **No authentication**: Cedar relies entirely on Cilium NetworkPolicy for access control. If a new caller needs to reach Cedar, the ingress Cilium policy must be updated in `talos-argocd-proxmox`.
- **`declaredBuild`/`declaredTest` hardcoded to `true`**: `coordinator/cedar.go` always sets both to `true` in the entity attrs regardless of what stages the pipeline actually declared. This means the stage-completion checks always fire. Revisit if teams need pipelines without a Build or Test stage.
