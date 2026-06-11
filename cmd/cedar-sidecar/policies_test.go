package main

import (
	"path/filepath"
	"runtime"
	"testing"

	cedar "github.com/cedar-policy/cedar-go"
)

func loadTestPolicies(t *testing.T) *cedar.PolicySet {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	dir := filepath.Join(filepath.Dir(thisFile), "..", "..", "policies")
	ps, err := loadPolicies(dir)
	if err != nil {
		t.Fatalf("loadPolicies: %v", err)
	}
	return ps
}

func euid(typ, id string) cedar.EntityUID {
	return cedar.EntityUID{Type: cedar.EntityType(typ), ID: cedar.String(id)}
}

func mkEntity(u cedar.EntityUID, attrs map[string]any, parents ...cedar.EntityUID) cedar.Entity {
	return cedar.Entity{
		UID:        u,
		Attributes: cedar.NewRecord(toRecordMap(attrs)),
		Parents:    cedar.NewEntityUIDSet(parents...),
	}
}

func mkEntities(es ...cedar.Entity) cedar.EntityMap {
	em := cedar.EntityMap{}
	for _, e := range es {
		em[e.UID] = e
	}
	return em
}

func runAuth(ps *cedar.PolicySet, principal, action, resource cedar.EntityUID, em cedar.EntityMap, ctx map[string]any) cedar.Decision {
	dec, _ := ps.IsAuthorized(em, cedar.Request{
		Principal: principal,
		Action:    action,
		Resource:  resource,
		Context:   cedar.NewRecord(toRecordMap(ctx)),
	})
	return dec
}

// --- shared test fixtures ----------------------------------------------------

var (
	pipelineUID = euid("TuxGrid::Pipeline", "teams/my-team/my-app")
	imageUID    = euid("TuxGrid::Image", "harbor.tuxgrid.com/my-team/my-app@sha256:abc")
	teamUID     = euid("TuxGrid::Team", "my-team")
	stagingNs   = euid("TuxGrid::Namespace", "staging")
	prodNs      = euid("TuxGrid::Namespace", "production")
	envUID      = euid("TuxGrid::Environment", "staging")
	prodEnvUID  = euid("TuxGrid::Environment", "production")

	attestAction = euid("TuxGrid::Action", "Attest")
	promoteAction = euid("TuxGrid::Action", "Promote")
	issueAction   = euid("TuxGrid::Action", "IssueCredentials")
	auditAction   = euid("TuxGrid::Action", "AuditCompliance")
)

func baseEntities(ns cedar.EntityUID, pipelineAttrs map[string]any) cedar.EntityMap {
	team := mkEntity(teamUID, map[string]any{"slug": "my-team", "coverageThreshold": float64(8000)}, ns)
	namespace := mkEntity(ns, map[string]any{"tier": ns.ID})
	image := mkEntity(imageUID, map[string]any{"digest": "sha256:abc", "repo": "harbor.tuxgrid.com/my-team/my-app"})
	pipeline := mkEntity(pipelineUID, pipelineAttrs, teamUID)
	return mkEntities(pipeline, team, namespace, image)
}

func goodPipelineAttrs() map[string]any {
	return map[string]any{
		"hasAuditId":     true,
		"triggeredBySCM": true,
		"declaredBuild":  true,
		"declaredTest":   true,
		"jobPath":        "teams/my-team/my-app",
		"branch":         "main",
	}
}

func goodAttestCtx() map[string]any {
	return map[string]any{
		"testsRun":                    float64(10),
		"testsFailed":                 float64(0),
		"lineCoveragePct":             float64(8500),
		"coverageThreshold":           float64(8000),
		"hasArtifactsJson":            true,
		"hasScanAttestation":          true,
		"scanAgeSeconds":              float64(3600),
		"completedStages":             []any{"Build", "Test"},
		"calledLibrarySteps":          []any{"jenkins-library::microservicePipeline", "jenkins-library::runTests", "jenkins-library::buildAndPushImage"},
		"auditAnomalyCount":           float64(0),
		"auditUnexpectedNetworkCount": float64(0),
	}
}

// --- attest-gate tests -------------------------------------------------------

func TestAttestGate_Allow(t *testing.T) {
	ps := loadTestPolicies(t)
	dec := runAuth(ps, pipelineUID, attestAction, imageUID, baseEntities(stagingNs, goodPipelineAttrs()), goodAttestCtx())
	if dec != cedar.Allow {
		t.Error("expected ALLOW for fully-compliant build")
	}
}

func TestAttestGate_DenyNoAuditId(t *testing.T) {
	ps := loadTestPolicies(t)
	attrs := goodPipelineAttrs()
	attrs["hasAuditId"] = false
	dec := runAuth(ps, pipelineUID, attestAction, imageUID, baseEntities(stagingNs, attrs), goodAttestCtx())
	if dec != cedar.Deny {
		t.Error("expected DENY: missing PLATFORM_AUDIT_ID")
	}
}

func TestAttestGate_DenyNoTests(t *testing.T) {
	ps := loadTestPolicies(t)
	ctx := goodAttestCtx()
	ctx["testsRun"] = float64(0)
	dec := runAuth(ps, pipelineUID, attestAction, imageUID, baseEntities(stagingNs, goodPipelineAttrs()), ctx)
	if dec != cedar.Deny {
		t.Error("expected DENY: zero tests run")
	}
}

func TestAttestGate_DenyFailingTests(t *testing.T) {
	ps := loadTestPolicies(t)
	ctx := goodAttestCtx()
	ctx["testsFailed"] = float64(2)
	dec := runAuth(ps, pipelineUID, attestAction, imageUID, baseEntities(stagingNs, goodPipelineAttrs()), ctx)
	if dec != cedar.Deny {
		t.Error("expected DENY: failing tests")
	}
}

func TestAttestGate_DenyCoverageBelowThreshold(t *testing.T) {
	ps := loadTestPolicies(t)
	ctx := goodAttestCtx()
	ctx["lineCoveragePct"] = float64(7000)
	ctx["coverageThreshold"] = float64(8000)
	dec := runAuth(ps, pipelineUID, attestAction, imageUID, baseEntities(stagingNs, goodPipelineAttrs()), ctx)
	if dec != cedar.Deny {
		t.Error("expected DENY: coverage below threshold")
	}
}

func TestAttestGate_DenyNoArtifactsJson(t *testing.T) {
	ps := loadTestPolicies(t)
	ctx := goodAttestCtx()
	ctx["hasArtifactsJson"] = false
	dec := runAuth(ps, pipelineUID, attestAction, imageUID, baseEntities(stagingNs, goodPipelineAttrs()), ctx)
	if dec != cedar.Deny {
		t.Error("expected DENY: no artifacts.json")
	}
}

func TestAttestGate_DenyManualTrigger(t *testing.T) {
	ps := loadTestPolicies(t)
	attrs := goodPipelineAttrs()
	attrs["triggeredBySCM"] = false
	dec := runAuth(ps, pipelineUID, attestAction, imageUID, baseEntities(stagingNs, attrs), goodAttestCtx())
	if dec != cedar.Deny {
		t.Error("expected DENY: manually triggered build")
	}
}

func TestAttestGate_DenyNoScanAttestation(t *testing.T) {
	ps := loadTestPolicies(t)
	ctx := goodAttestCtx()
	ctx["hasScanAttestation"] = false
	dec := runAuth(ps, pipelineUID, attestAction, imageUID, baseEntities(stagingNs, goodPipelineAttrs()), ctx)
	if dec != cedar.Deny {
		t.Error("expected DENY: no scan attestation")
	}
}

func TestAttestGate_DenyBuildNotCompleted(t *testing.T) {
	ps := loadTestPolicies(t)
	ctx := goodAttestCtx()
	ctx["completedStages"] = []any{"Test"} // Build declared but not in completedStages
	dec := runAuth(ps, pipelineUID, attestAction, imageUID, baseEntities(stagingNs, goodPipelineAttrs()), ctx)
	if dec != cedar.Deny {
		t.Error("expected DENY: Build stage declared but did not complete")
	}
}

func TestAttestGate_DenyMissingLibraryCall(t *testing.T) {
	ps := loadTestPolicies(t)
	ctx := goodAttestCtx()
	ctx["calledLibrarySteps"] = []any{"jenkins-library::runTests"} // microservicePipeline missing
	dec := runAuth(ps, pipelineUID, attestAction, imageUID, baseEntities(stagingNs, goodPipelineAttrs()), ctx)
	if dec != cedar.Deny {
		t.Error("expected DENY: microservicePipeline not called")
	}
}

func TestAttestGate_DenyAuditAnomaly(t *testing.T) {
	ps := loadTestPolicies(t)
	ctx := goodAttestCtx()
	ctx["auditAnomalyCount"] = float64(1)
	dec := runAuth(ps, pipelineUID, attestAction, imageUID, baseEntities(stagingNs, goodPipelineAttrs()), ctx)
	if dec != cedar.Deny {
		t.Error("expected DENY: audit anomaly detected")
	}
}

func TestAttestGate_DenyUnexpectedNetwork(t *testing.T) {
	ps := loadTestPolicies(t)
	ctx := goodAttestCtx()
	ctx["auditUnexpectedNetworkCount"] = float64(1)
	dec := runAuth(ps, pipelineUID, attestAction, imageUID, baseEntities(stagingNs, goodPipelineAttrs()), ctx)
	if dec != cedar.Deny {
		t.Error("expected DENY: unexpected network connection")
	}
}

// --- promote-gate tests ------------------------------------------------------

func goodPromoteCtx(tier string) map[string]any {
	return map[string]any{
		"targetTier": tier,
		"attestationTypes": []any{
			"https://tuxgrid.com/attestation/build/v1",
			"https://tuxgrid.com/attestation/tests/v1",
			"https://tuxgrid.com/attestation/scan/v1",
			"https://tuxgrid.com/attestation/pipeline/v1",
			"slsaprovenance1",
			"cyclonedx",
		},
		"scanAgeSeconds": float64(3600),
	}
}

func TestPromoteGate_AllowStaging(t *testing.T) {
	ps := loadTestPolicies(t)
	dec := runAuth(ps, pipelineUID, promoteAction, imageUID, baseEntities(stagingNs, goodPipelineAttrs()), goodPromoteCtx("staging"))
	if dec != cedar.Allow {
		t.Error("expected ALLOW: staging promote with all attestations")
	}
}

func TestPromoteGate_AllowProduction(t *testing.T) {
	ps := loadTestPolicies(t)
	dec := runAuth(ps, pipelineUID, promoteAction, imageUID, baseEntities(prodNs, goodPipelineAttrs()), goodPromoteCtx("production"))
	if dec != cedar.Allow {
		t.Error("expected ALLOW: production promote with all attestations and fresh scan")
	}
}

func TestPromoteGate_DenyProductionMissingAttestation(t *testing.T) {
	ps := loadTestPolicies(t)
	ctx := goodPromoteCtx("production")
	ctx["attestationTypes"] = []any{
		"https://tuxgrid.com/attestation/build/v1",
		"https://tuxgrid.com/attestation/tests/v1",
		// scan/v1 and pipeline/v1 missing
	}
	dec := runAuth(ps, pipelineUID, promoteAction, imageUID, baseEntities(prodNs, goodPipelineAttrs()), ctx)
	if dec != cedar.Deny {
		t.Error("expected DENY: production promote missing attestation types")
	}
}

func TestPromoteGate_DenyProductionStaleScan(t *testing.T) {
	ps := loadTestPolicies(t)
	ctx := goodPromoteCtx("production")
	ctx["scanAgeSeconds"] = float64(90000) // >24h
	dec := runAuth(ps, pipelineUID, promoteAction, imageUID, baseEntities(prodNs, goodPipelineAttrs()), ctx)
	if dec != cedar.Deny {
		t.Error("expected DENY: production promote with stale scan")
	}
}

func TestPromoteGate_AllowStagingMissingAttestation(t *testing.T) {
	ps := loadTestPolicies(t)
	ctx := goodPromoteCtx("staging")
	ctx["attestationTypes"] = []any{"https://tuxgrid.com/attestation/build/v1"}
	dec := runAuth(ps, pipelineUID, promoteAction, imageUID, baseEntities(stagingNs, goodPipelineAttrs()), ctx)
	if dec != cedar.Allow {
		t.Error("expected ALLOW: staging promote does not require all attestations")
	}
}

// --- token-gate tests --------------------------------------------------------

func mkTeamEntities() cedar.EntityMap {
	team := mkEntity(teamUID, map[string]any{"slug": "my-team", "coverageThreshold": float64(8000)}, stagingNs)
	ns := mkEntity(stagingNs, map[string]any{"tier": "staging"})
	env := mkEntity(envUID, map[string]any{"tier": "staging"})
	prodEnv := mkEntity(prodEnvUID, map[string]any{"tier": "production"})
	return mkEntities(team, ns, env, prodEnv)
}

func goodTokenCtx(env string) map[string]any {
	return map[string]any{
		"role_arn":    "arn:aws:iam::123456789012:role/my-team-staging",
		"image_ref":   "harbor.tuxgrid.com/my-team/my-app@sha256:abc",
		"environment": env,
		"scanAttestationVerified": true,
		"attestationTypes": []any{
			"https://tuxgrid.com/attestation/build/v1",
			"https://tuxgrid.com/attestation/tests/v1",
			"https://tuxgrid.com/attestation/scan/v1",
			"https://tuxgrid.com/attestation/pipeline/v1",
			"slsaprovenance1",
			"cyclonedx",
		},
	}
}

func TestTokenGate_AllowStaging(t *testing.T) {
	ps := loadTestPolicies(t)
	dec := runAuth(ps, teamUID, issueAction, envUID, mkTeamEntities(), goodTokenCtx("staging"))
	if dec != cedar.Allow {
		t.Error("expected ALLOW: staging credential issuance with scan verified")
	}
}

func TestTokenGate_AllowProduction(t *testing.T) {
	ps := loadTestPolicies(t)
	dec := runAuth(ps, teamUID, issueAction, prodEnvUID, mkTeamEntities(), goodTokenCtx("production"))
	if dec != cedar.Allow {
		t.Error("expected ALLOW: production credential issuance with all attestations")
	}
}

func TestTokenGate_DenyNoScanVerification(t *testing.T) {
	ps := loadTestPolicies(t)
	ctx := goodTokenCtx("staging")
	ctx["scanAttestationVerified"] = false
	dec := runAuth(ps, teamUID, issueAction, envUID, mkTeamEntities(), ctx)
	if dec != cedar.Deny {
		t.Error("expected DENY: scan attestation not verified")
	}
}

func TestTokenGate_DenyProductionMissingAttestation(t *testing.T) {
	ps := loadTestPolicies(t)
	ctx := goodTokenCtx("production")
	ctx["attestationTypes"] = []any{
		"https://tuxgrid.com/attestation/build/v1",
		"https://tuxgrid.com/attestation/scan/v1",
		// tests/v1 and pipeline/v1 missing
	}
	dec := runAuth(ps, teamUID, issueAction, prodEnvUID, mkTeamEntities(), ctx)
	if dec != cedar.Deny {
		t.Error("expected DENY: production credentials require all four attestation types")
	}
}

// --- audit-gap tests ---------------------------------------------------------

func mkAuditEntities() cedar.EntityMap {
	team := mkEntity(teamUID, map[string]any{"slug": "my-team", "coverageThreshold": float64(8000)}, stagingNs)
	ns := mkEntity(stagingNs, map[string]any{"tier": "staging"})
	pipeline := mkEntity(pipelineUID, goodPipelineAttrs(), teamUID)
	return mkEntities(team, ns, pipeline)
}

func TestAuditGap_AllowHealthyPipeline(t *testing.T) {
	ps := loadTestPolicies(t)
	ctx := map[string]any{
		"lastAttestationAgeSeconds": float64(3600),
		"attestationTypes": []any{
			"https://tuxgrid.com/attestation/build/v1",
			"https://tuxgrid.com/attestation/scan/v1",
		},
	}
	dec := runAuth(ps, teamUID, auditAction, pipelineUID, mkAuditEntities(), ctx)
	if dec != cedar.Allow {
		t.Error("expected ALLOW: pipeline with recent attestation")
	}
}

func TestAuditGap_DenyNeverAttested(t *testing.T) {
	ps := loadTestPolicies(t)
	ctx := map[string]any{
		"lastAttestationAgeSeconds": float64(9223372036854775806), // sentinel max
		"attestationTypes":          []any{},
	}
	dec := runAuth(ps, teamUID, auditAction, pipelineUID, mkAuditEntities(), ctx)
	if dec != cedar.Deny {
		t.Error("expected DENY: pipeline has never attested")
	}
}

func TestAuditGap_DenyStale7Days(t *testing.T) {
	ps := loadTestPolicies(t)
	ctx := map[string]any{
		"lastAttestationAgeSeconds": float64(700000), // >7 days
		"attestationTypes": []any{
			"https://tuxgrid.com/attestation/scan/v1",
		},
	}
	dec := runAuth(ps, teamUID, auditAction, pipelineUID, mkAuditEntities(), ctx)
	if dec != cedar.Deny {
		t.Error("expected DENY: no attestation in 7 days")
	}
}

func TestAuditGap_DenyNoScanAttestation(t *testing.T) {
	ps := loadTestPolicies(t)
	ctx := map[string]any{
		"lastAttestationAgeSeconds": float64(3600),
		"attestationTypes": []any{
			"https://tuxgrid.com/attestation/build/v1",
			// scan/v1 missing
		},
	}
	dec := runAuth(ps, teamUID, auditAction, pipelineUID, mkAuditEntities(), ctx)
	if dec != cedar.Deny {
		t.Error("expected DENY: pipeline has never produced scan/v1 attestation")
	}
}

// --- strict-tier (no-custom-jenkinsfile) + witness-dark tests ---------------

func strictPipelineAttrs() map[string]any {
	a := goodPipelineAttrs()
	a["strictPipeline"] = true
	return a
}

func strictAttestCtx() map[string]any {
	c := goodAttestCtx()
	c["jenkinsfileApproved"] = true
	c["customStepCount"] = float64(0)
	c["sandboxViolationCount"] = float64(0)
	c["tetragonExecsObserved"] = float64(12)
	c["groovyRuntimeCalls"] = float64(7)
	return c
}

func TestStrict_AllowThinPipeline(t *testing.T) {
	ps := loadTestPolicies(t)
	dec := runAuth(ps, pipelineUID, attestAction, imageUID, baseEntities(stagingNs, strictPipelineAttrs()), strictAttestCtx())
	if dec != cedar.Allow {
		t.Error("expected ALLOW: strict thin pipeline with no violations")
	}
}

func TestStrict_DenyCustomStep(t *testing.T) {
	ps := loadTestPolicies(t)
	ctx := strictAttestCtx()
	ctx["customStepCount"] = float64(1)
	dec := runAuth(ps, pipelineUID, attestAction, imageUID, baseEntities(stagingNs, strictPipelineAttrs()), ctx)
	if dec != cedar.Deny {
		t.Error("expected DENY: strict pipeline ran a custom step outside jenkins-library")
	}
}

func TestStrict_DenyUnapprovedJenkinsfile(t *testing.T) {
	ps := loadTestPolicies(t)
	ctx := strictAttestCtx()
	ctx["jenkinsfileApproved"] = false
	dec := runAuth(ps, pipelineUID, attestAction, imageUID, baseEntities(stagingNs, strictPipelineAttrs()), ctx)
	if dec != cedar.Deny {
		t.Error("expected DENY: strict pipeline Jenkinsfile not an approved thin template")
	}
}

func TestStrict_DenySandboxViolation(t *testing.T) {
	ps := loadTestPolicies(t)
	ctx := strictAttestCtx()
	ctx["sandboxViolationCount"] = float64(1)
	dec := runAuth(ps, pipelineUID, attestAction, imageUID, baseEntities(stagingNs, strictPipelineAttrs()), ctx)
	if dec != cedar.Deny {
		t.Error("expected DENY: strict pipeline attempted a blocked Groovy operation")
	}
}

func TestStrict_NonStrictUnaffected(t *testing.T) {
	ps := loadTestPolicies(t)
	// A non-strict pipeline with custom steps, unapproved Jenkinsfile, and a sandbox
	// violation must still ALLOW — strict rules are gated on principal.strictPipeline.
	ctx := goodAttestCtx()
	ctx["customStepCount"] = float64(5)
	ctx["jenkinsfileApproved"] = false
	ctx["sandboxViolationCount"] = float64(3)
	dec := runAuth(ps, pipelineUID, attestAction, imageUID, baseEntities(stagingNs, goodPipelineAttrs()), ctx)
	if dec != cedar.Allow {
		t.Error("expected ALLOW: non-strict pipeline is unaffected by strict-tier rules")
	}
}

func TestWitnessDark_DenyStrict(t *testing.T) {
	ps := loadTestPolicies(t)
	ctx := strictAttestCtx()
	ctx["tetragonExecsObserved"] = float64(0)
	dec := runAuth(ps, pipelineUID, attestAction, imageUID, baseEntities(stagingNs, strictPipelineAttrs()), ctx)
	if dec != cedar.Deny {
		t.Error("expected DENY: strict pipeline with dark Tetragon witness (execs==0)")
	}
}

func TestWitnessDark_NonStrictUnaffected(t *testing.T) {
	ps := loadTestPolicies(t)
	ctx := goodAttestCtx()
	ctx["tetragonExecsObserved"] = float64(0)
	dec := runAuth(ps, pipelineUID, attestAction, imageUID, baseEntities(stagingNs, goodPipelineAttrs()), ctx)
	if dec != cedar.Allow {
		t.Error("expected ALLOW: non-strict pipeline unaffected by witness-dark rule")
	}
}

func TestTracerDark_DenyStrict(t *testing.T) {
	ps := loadTestPolicies(t)
	ctx := strictAttestCtx()
	ctx["groovyRuntimeCalls"] = float64(0)
	dec := runAuth(ps, pipelineUID, attestAction, imageUID, baseEntities(stagingNs, strictPipelineAttrs()), ctx)
	if dec != cedar.Deny {
		t.Error("expected DENY: strict pipeline with dark Groovy runtime tracer (0 events)")
	}
}

func TestTracerDark_NonStrictUnaffected(t *testing.T) {
	ps := loadTestPolicies(t)
	ctx := goodAttestCtx()
	ctx["groovyRuntimeCalls"] = float64(0)
	dec := runAuth(ps, pipelineUID, attestAction, imageUID, baseEntities(stagingNs, goodPipelineAttrs()), ctx)
	if dec != cedar.Allow {
		t.Error("expected ALLOW: non-strict pipeline unaffected by tracer-dark rule")
	}
}
