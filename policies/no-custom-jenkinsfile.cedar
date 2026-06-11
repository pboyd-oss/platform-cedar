// no-custom-jenkinsfile.cedar
//
// OPT-IN strict tier. Denies Attest for a build that ran pipeline steps outside the
// platform shared library (a custom Jenkinsfile, an inline script{} block, or
// microservicePipeline hook closures) -- but ONLY for pipelines that opted in via the
// Jenkins folder property TUXGRID_STRICT_PIPELINE=true (-> principal.strictPipeline).
//
// Every other pipeline is unaffected: attest-gate.cedar still applies, custom
// Jenkinsfiles are allowed, they simply earn nothing unless they pass the gates. This
// file only adds teeth for namespaces/pipelines that explicitly want platform-pipeline-only.
//
// context.customStepCount = STEP_ATOM flow nodes with calledFrom == null and
// librarySource.source != "library" (a leaf step the team invoked directly, not via a
// jenkins-library step). Populated by PlatformAuditGraphListener -> shim -> coordinator.
// This is FlowNode-based, so it catches custom *steps*; raw script-level Groovy
// ("x".execute(), @NonCPS) emits no node and is caught instead by the
// auditAnomalyCount / auditUnexpectedNetworkCount (Tetragon) rules in attest-gate.cedar.
//
// Schema fields are optional + has-guarded so Promote and any other Pipeline-principal
// authorize calls that do not send them are unaffected.

@reason("strict pipeline: custom steps ran outside jenkins-library -- custom Jenkinsfiles are not permitted for this pipeline")
forbid (
  principal is TuxGrid::Pipeline,
  action == TuxGrid::Action::"Attest",
  resource is TuxGrid::Image
)
when {
  principal has strictPipeline && principal.strictPipeline &&
  context has customStepCount && context.customStepCount > 0
};

// ---- FUTURE (source-level, catches raw Groovy too) ----------------------------------
// Enable once the source-scan job parses the repo Jenkinsfile and the coordinator emits
// context.jenkinsfileApproved (add it to the schema + cedar.go ctx first):
//
// @reason("strict pipeline: Jenkinsfile does not match an approved platform template")
// forbid (
//   principal is TuxGrid::Pipeline,
//   action == TuxGrid::Action::"Attest",
//   resource is TuxGrid::Image
// )
// when {
//   principal has strictPipeline && principal.strictPipeline &&
//   (!(context has jenkinsfileApproved) || !context.jenkinsfileApproved)
// };
