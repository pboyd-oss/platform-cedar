permit (
  principal is TuxGrid::Pipeline,
  action == TuxGrid::Action::"Attest",
  resource is TuxGrid::Image
);

@reason("PLATFORM_AUDIT_ID missing — audit-graph-listener was not active for this build")
forbid (
  principal is TuxGrid::Pipeline,
  action == TuxGrid::Action::"Attest",
  resource is TuxGrid::Image
)
unless { principal.hasAuditId };

@reason("no JUnit tests recorded for this build")
forbid (
  principal is TuxGrid::Pipeline,
  action == TuxGrid::Action::"Attest",
  resource is TuxGrid::Image
)
when { context.testsRun == 0 };

@reason("build has failing tests")
forbid (
  principal is TuxGrid::Pipeline,
  action == TuxGrid::Action::"Attest",
  resource is TuxGrid::Image
)
when { context.testsFailed > 0 };

@reason("line coverage below team threshold")
forbid (
  principal is TuxGrid::Pipeline,
  action == TuxGrid::Action::"Attest",
  resource is TuxGrid::Image
)
when { context.lineCoveragePct < context.coverageThreshold };

@reason("artifacts.json not archived — image list unknown")
forbid (
  principal is TuxGrid::Pipeline,
  action == TuxGrid::Action::"Attest",
  resource is TuxGrid::Image
)
unless { context.hasArtifactsJson };

@reason("build was manually triggered, not by SCM event")
forbid (
  principal is TuxGrid::Pipeline,
  action == TuxGrid::Action::"Attest",
  resource is TuxGrid::Image
)
unless { principal.triggeredBySCM };

@reason("scan/v1 attestation missing or stale for production-bound image")
forbid (
  principal is TuxGrid::Pipeline,
  action == TuxGrid::Action::"Attest",
  resource is TuxGrid::Image
)
when {
  !context.hasScanAttestation ||
  (context.scanAgeSeconds > 7200 && principal in TuxGrid::Namespace::"production")
};

@reason("Build stage declared but did not complete")
forbid (
  principal is TuxGrid::Pipeline,
  action == TuxGrid::Action::"Attest",
  resource is TuxGrid::Image
)
when {
  principal.declaredBuild &&
  !context.completedStages.contains("Build")
};

@reason("Test stage declared but did not complete")
forbid (
  principal is TuxGrid::Pipeline,
  action == TuxGrid::Action::"Attest",
  resource is TuxGrid::Image
)
when {
  principal.declaredTest &&
  !context.completedStages.contains("Test")
};

@reason("Release stage ran without a preceding Build stage")
forbid (
  principal is TuxGrid::Pipeline,
  action == TuxGrid::Action::"Attest",
  resource is TuxGrid::Image
)
when {
  context.completedStages.contains("Release") &&
  !context.completedStages.contains("Build")
};

@reason("microservicePipeline from jenkins-library was not invoked — pipeline may not meet platform standards")
forbid (
  principal is TuxGrid::Pipeline,
  action == TuxGrid::Action::"Attest",
  resource is TuxGrid::Image
)
unless { context.calledLibrarySteps.contains("jenkins-library::microservicePipeline") };

@reason("build executed processes outside declared pipeline steps — possible supply chain injection")
forbid (
  principal is TuxGrid::Pipeline,
  action == TuxGrid::Action::"Attest",
  resource is TuxGrid::Image
)
when { context.auditAnomalyCount > 0 };

@reason("build made network connections outside declared pipeline steps — possible exfiltration or C2")
forbid (
  principal is TuxGrid::Pipeline,
  action == TuxGrid::Action::"Attest",
  resource is TuxGrid::Image
)
when { context.auditUnexpectedNetworkCount > 0 };
