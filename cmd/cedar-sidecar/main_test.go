package main

import (
	"encoding/json"
	"slices"
	"testing"

	cedar "github.com/cedar-policy/cedar-go"
)

var testPolicies *cedar.PolicySet

func init() {
	ps, err := loadPolicies("../../policies")
	if err != nil {
		panic("failed to load policies: " + err.Error())
	}
	testPolicies = ps
}

// passingCtx returns a context that satisfies all attest-gate policies.
func passingCtx() map[string]any {
	return map[string]any{
		"testsRun":                    float64(42),
		"testsFailed":                 float64(0),
		"lineCoveragePct":             float64(85),
		"coverageThreshold":           float64(70),
		"hasArtifactsJson":            true,
		"hasScanAttestation":          true,
		"scanAgeSeconds":              float64(0),
		"completedStages":             []any{"Test", "Build", "Release"},
		"calledLibrarySteps":          []any{"jenkins-library::microservicePipeline", "jenkins-library::runTests", "jenkins-library::buildApp"},
		"auditAnomalyCount":           float64(0),
		"auditUnexpectedNetworkCount": float64(0),
	}
}

// passingEntities returns a full entity set for a development pipeline.
func passingEntities() cedar.EntityMap {
	ns := cedar.NewEntityUID("TuxGrid::Namespace", "development")
	team := cedar.NewEntityUID("TuxGrid::Team", "my-team")
	pipeline := cedar.NewEntityUID("TuxGrid::Pipeline", "teams/my-team/my-service")

	return cedar.EntityMap{
		ns: cedar.Entity{
			UID:     ns,
			Attributes: cedar.NewRecord(cedar.RecordMap{
				"tier": cedar.String("development"),
			}),
		},
		team: cedar.Entity{
			UID:     team,
			Parents: cedar.NewEntityUIDSet(ns),
			Attributes: cedar.NewRecord(cedar.RecordMap{
				"slug":              cedar.String("my-team"),
				"coverageThreshold": cedar.Long(70),
			}),
		},
		pipeline: cedar.Entity{
			UID:     pipeline,
			Parents: cedar.NewEntityUIDSet(team),
			Attributes: cedar.NewRecord(cedar.RecordMap{
				"jobPath":        cedar.String("teams/my-team/my-service"),
				"branch":         cedar.String("main"),
				"triggeredBySCM": cedar.Boolean(true),
				"hasAuditId":     cedar.Boolean(true),
				"declaredBuild":  cedar.Boolean(true),
				"declaredTest":   cedar.Boolean(true),
			}),
		},
	}
}

func authorize(t *testing.T, entities cedar.EntityMap, ctx map[string]any) (string, []string) {
	t.Helper()

	var principal cedar.EntityUID
	if err := principal.UnmarshalCedar([]byte(`TuxGrid::Pipeline::"teams/my-team/my-service"`)); err != nil {
		t.Fatalf("principal: %v", err)
	}
	var action cedar.EntityUID
	if err := action.UnmarshalCedar([]byte(`TuxGrid::Action::"Attest"`)); err != nil {
		t.Fatalf("action: %v", err)
	}
	var resource cedar.EntityUID
	if err := resource.UnmarshalCedar([]byte(`TuxGrid::Image::"sha256:abc123"`)); err != nil {
		t.Fatalf("resource: %v", err)
	}

	decision, diag := testPolicies.IsAuthorized(entities, cedar.Request{
		Principal: principal,
		Action:    action,
		Resource:  resource,
		Context:   cedar.NewRecord(toRecordMap(ctx)),
	})

	d := "DENY"
	if decision == cedar.Allow {
		d = "ALLOW"
	}

	var reasons []string
	for _, r := range diag.Reasons {
		p := testPolicies.Get(r.PolicyID)
		if p == nil {
			continue
		}
		if msg, ok := p.Annotations()["reason"]; ok {
			reasons = append(reasons, string(msg))
		}
	}
	return d, reasons
}

func TestAttest_Allow(t *testing.T) {
	decision, reasons := authorize(t, passingEntities(), passingCtx())
	if decision != "ALLOW" {
		t.Errorf("expected ALLOW, got DENY: %v", reasons)
	}
}

func TestAttest_Deny_NoTests(t *testing.T) {
	ctx := passingCtx()
	ctx["testsRun"] = float64(0)

	decision, reasons := authorize(t, passingEntities(), ctx)
	if decision != "DENY" {
		t.Errorf("expected DENY, got ALLOW")
	}
	if !slices.Contains(reasons, "no JUnit tests recorded for this build") {
		t.Errorf("expected 'no JUnit tests' reason, got: %v", reasons)
	}
}

func TestAttest_Deny_FailingTests(t *testing.T) {
	ctx := passingCtx()
	ctx["testsFailed"] = float64(3)

	decision, reasons := authorize(t, passingEntities(), ctx)
	if decision != "DENY" {
		t.Errorf("expected DENY, got ALLOW")
	}
	if !slices.Contains(reasons, "build has failing tests") {
		t.Errorf("expected 'failing tests' reason, got: %v", reasons)
	}
}

func TestAttest_Deny_LowCoverage(t *testing.T) {
	ctx := passingCtx()
	ctx["lineCoveragePct"] = float64(50)

	decision, reasons := authorize(t, passingEntities(), ctx)
	if decision != "DENY" {
		t.Errorf("expected DENY, got ALLOW")
	}
	if !slices.Contains(reasons, "line coverage below team threshold") {
		t.Errorf("expected coverage reason, got: %v", reasons)
	}
}

func TestAttest_Deny_NoArtifacts(t *testing.T) {
	ctx := passingCtx()
	ctx["hasArtifactsJson"] = false

	decision, reasons := authorize(t, passingEntities(), ctx)
	if decision != "DENY" {
		t.Errorf("expected DENY, got ALLOW")
	}
	if !slices.Contains(reasons, "artifacts.json not archived — image list unknown") {
		t.Errorf("expected artifacts reason, got: %v", reasons)
	}
}

func TestAttest_Deny_ManualTrigger(t *testing.T) {
	entities := passingEntities()
	pipeline := cedar.NewEntityUID("TuxGrid::Pipeline", "teams/my-team/my-service")
	team := cedar.NewEntityUID("TuxGrid::Team", "my-team")
	entities[pipeline] = cedar.Entity{
		UID:     pipeline,
		Parents: cedar.NewEntityUIDSet(team),
		Attributes: cedar.NewRecord(cedar.RecordMap{
			"jobPath":        cedar.String("teams/my-team/my-service"),
			"branch":         cedar.String("main"),
			"triggeredBySCM": cedar.Boolean(false),
			"hasAuditId":     cedar.Boolean(true),
			"declaredBuild":  cedar.Boolean(true),
			"declaredTest":   cedar.Boolean(true),
		}),
	}

	decision, reasons := authorize(t, entities, passingCtx())
	if decision != "DENY" {
		t.Errorf("expected DENY, got ALLOW")
	}
	if !slices.Contains(reasons, "build was manually triggered, not by SCM event") {
		t.Errorf("expected SCM trigger reason, got: %v", reasons)
	}
}

func TestAttest_Deny_NoScan(t *testing.T) {
	ctx := passingCtx()
	ctx["hasScanAttestation"] = false

	decision, reasons := authorize(t, passingEntities(), ctx)
	if decision != "DENY" {
		t.Errorf("expected DENY, got ALLOW")
	}
	if !slices.Contains(reasons, "scan/v1 attestation missing or stale for production-bound image") {
		t.Errorf("expected scan reason, got: %v", reasons)
	}
}

func TestAttest_Deny_MissingLibraryStep(t *testing.T) {
	ctx := passingCtx()
	ctx["calledLibrarySteps"] = []any{"jenkins-library::someOtherStep"}

	decision, reasons := authorize(t, passingEntities(), ctx)
	if decision != "DENY" {
		t.Errorf("expected DENY, got ALLOW")
	}
	if !slices.Contains(reasons, "microservicePipeline from jenkins-library was not invoked — pipeline may not meet platform standards") {
		t.Errorf("expected library step reason, got: %v", reasons)
	}
}

func TestAttest_Deny_ReleaseWithoutBuild(t *testing.T) {
	ctx := passingCtx()
	ctx["completedStages"] = []any{"Test", "Release"}

	decision, reasons := authorize(t, passingEntities(), ctx)
	if decision != "DENY" {
		t.Errorf("expected DENY, got ALLOW")
	}
	if !slices.Contains(reasons, "Release stage ran without a preceding Build stage") {
		t.Errorf("expected ordering reason, got: %v", reasons)
	}
}

func TestAttest_Deny_MissingAuditId(t *testing.T) {
	entities := passingEntities()
	pipeline := cedar.NewEntityUID("TuxGrid::Pipeline", "teams/my-team/my-service")
	team := cedar.NewEntityUID("TuxGrid::Team", "my-team")
	entities[pipeline] = cedar.Entity{
		UID:     pipeline,
		Parents: cedar.NewEntityUIDSet(team),
		Attributes: cedar.NewRecord(cedar.RecordMap{
			"jobPath":        cedar.String("teams/my-team/my-service"),
			"branch":         cedar.String("main"),
			"triggeredBySCM": cedar.Boolean(true),
			"hasAuditId":     cedar.Boolean(false),
			"declaredBuild":  cedar.Boolean(true),
			"declaredTest":   cedar.Boolean(true),
		}),
	}

	decision, reasons := authorize(t, entities, passingCtx())
	if decision != "DENY" {
		t.Errorf("expected DENY, got ALLOW")
	}
	if !slices.Contains(reasons, "PLATFORM_AUDIT_ID missing — audit-graph-listener was not active for this build") {
		t.Errorf("expected audit ID reason, got: %v", reasons)
	}
}

func TestAttest_Deny_TestStageBypassedLibrary(t *testing.T) {
	ctx := passingCtx()
	ctx["calledLibrarySteps"] = []any{"jenkins-library::microservicePipeline", "jenkins-library::buildApp"}

	decision, reasons := authorize(t, passingEntities(), ctx)
	if decision != "DENY" {
		t.Errorf("expected DENY, got ALLOW")
	}
	if !slices.Contains(reasons, "Test stage ran but runTests from jenkins-library was not called — platform test runner was bypassed") {
		t.Errorf("expected runTests reason, got: %v", reasons)
	}
}

func TestAttest_Deny_BuildStageBypassedLibrary(t *testing.T) {
	ctx := passingCtx()
	ctx["calledLibrarySteps"] = []any{"jenkins-library::microservicePipeline", "jenkins-library::runTests"}

	decision, reasons := authorize(t, passingEntities(), ctx)
	if decision != "DENY" {
		t.Errorf("expected DENY, got ALLOW")
	}
	if !slices.Contains(reasons, "Build stage ran but no platform build step was called — image may not have been built through platform tooling") {
		t.Errorf("expected build step reason, got: %v", reasons)
	}
}

func TestAttest_Deny_AuditAnomaly(t *testing.T) {
	ctx := passingCtx()
	ctx["auditAnomalyCount"] = float64(2)

	decision, reasons := authorize(t, passingEntities(), ctx)
	if decision != "DENY" {
		t.Errorf("expected DENY, got ALLOW")
	}
	if !slices.Contains(reasons, "build executed processes outside declared pipeline steps — possible supply chain injection") {
		t.Errorf("expected anomaly reason, got: %v", reasons)
	}
}

func TestAttest_Deny_UnexpectedNetwork(t *testing.T) {
	ctx := passingCtx()
	ctx["auditUnexpectedNetworkCount"] = float64(1)

	decision, reasons := authorize(t, passingEntities(), ctx)
	if decision != "DENY" {
		t.Errorf("expected DENY, got ALLOW")
	}
	if !slices.Contains(reasons, "build made network connections outside declared pipeline steps — possible exfiltration or C2") {
		t.Errorf("expected unexpected network reason, got: %v", reasons)
	}
}

func TestHealthz(t *testing.T) {
	b, _ := json.Marshal(AuthorizeResponse{Decision: "ALLOW", Reasons: nil})
	var resp AuthorizeResponse
	if err := json.Unmarshal(b, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Decision != "ALLOW" {
		t.Errorf("unexpected decision: %v", resp.Decision)
	}
}
