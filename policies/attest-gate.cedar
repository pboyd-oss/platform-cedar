// Blanket permit — forbids below override on match
permit (
  principal is TuxGrid::Pipeline,
  action == TuxGrid::Action::"Attest",
  resource is TuxGrid::Image
);

// Standard 0: PLATFORM_AUDIT_ID must be present
forbid (
  principal is TuxGrid::Pipeline,
  action == TuxGrid::Action::"Attest",
  resource is TuxGrid::Image
)
unless { principal.hasAuditId }
annotations { "reason": "PLATFORM_AUDIT_ID missing — audit-graph-listener was not active for this build" };

// Standard 1: tests must have run
forbid (
  principal is TuxGrid::Pipeline,
  action == TuxGrid::Action::"Attest",
  resource is TuxGrid::Image
)
when { context.testsRun == 0 }
annotations { "reason": "no JUnit tests recorded for this build" };

// Standard 2: no test failures
forbid (
  principal is TuxGrid::Pipeline,
  action == TuxGrid::Action::"Attest",
  resource is TuxGrid::Image
)
when { context.testsFailed > 0 }
annotations { "reason": "build has failing tests" };

// Standard 3: coverage meets team threshold
forbid (
  principal is TuxGrid::Pipeline,
  action == TuxGrid::Action::"Attest",
  resource is TuxGrid::Image
)
when { context.lineCoveragePct < context.coverageThreshold }
annotations { "reason": "line coverage below team threshold" };

// Standard 4: artifacts.json must be archived
forbid (
  principal is TuxGrid::Pipeline,
  action == TuxGrid::Action::"Attest",
  resource is TuxGrid::Image
)
unless { context.hasArtifactsJson }
annotations { "reason": "artifacts.json not archived — image list unknown" };

// Standard 5: must be SCM-triggered
forbid (
  principal is TuxGrid::Pipeline,
  action == TuxGrid::Action::"Attest",
  resource is TuxGrid::Image
)
unless { principal.triggeredBySCM }
annotations { "reason": "build was manually triggered, not by SCM event" };

// Standard 6: scan attestation required and fresh for production
forbid (
  principal is TuxGrid::Pipeline,
  action == TuxGrid::Action::"Attest",
  resource is TuxGrid::Image
)
when {
  !context.hasScanAttestation ||
  (context.scanAgeSeconds > 7200 && principal in TuxGrid::Namespace::"production")
}
annotations { "reason": "scan/v1 attestation missing or stale for production-bound image" };

// Standard 7: Build stage must have completed if team declared it
forbid (
  principal is TuxGrid::Pipeline,
  action == TuxGrid::Action::"Attest",
  resource is TuxGrid::Image
)
when {
  principal.declaredBuild &&
  !context.completedStages.contains("Build")
}
annotations { "reason": "Build stage declared but did not complete" };

// Standard 8: Test stage must have completed if team declared it
forbid (
  principal is TuxGrid::Pipeline,
  action == TuxGrid::Action::"Attest",
  resource is TuxGrid::Image
)
when {
  principal.declaredTest &&
  !context.completedStages.contains("Test")
}
annotations { "reason": "Test stage declared but did not complete" };

// Standard 9: Release must not have run without Build
forbid (
  principal is TuxGrid::Pipeline,
  action == TuxGrid::Action::"Attest",
  resource is TuxGrid::Image
)
when {
  context.completedStages.contains("Release") &&
  !context.completedStages.contains("Build")
}
annotations { "reason": "Release stage ran without a preceding Build stage" };

// Standard 10: microservicePipeline from jenkins-library must have been called
forbid (
  principal is TuxGrid::Pipeline,
  action == TuxGrid::Action::"Attest",
  resource is TuxGrid::Image
)
unless { context.calledLibrarySteps.contains("jenkins-library::microservicePipeline") }
annotations { "reason": "microservicePipeline from jenkins-library was not invoked — pipeline may not meet platform standards" };
