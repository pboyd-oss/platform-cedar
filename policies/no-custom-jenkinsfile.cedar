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

// Source-level gate (catches raw script-level Groovy that emits no FlowNode, which
// customStepCount cannot see). context.jenkinsfileApproved is set by the shim: it reads
// the pipeline script via CpsFlowExecution and checks it is a "thin" Jenkinsfile
// (invokes microservicePipeline and contains no script{}/node{}/sh/.execute()/@NonCPS/
// reflection). Fail-closed for strict pipelines: absent or false => deny.
@reason("strict pipeline: Jenkinsfile is not an approved thin platform template")
forbid (
  principal is TuxGrid::Pipeline,
  action == TuxGrid::Action::"Attest",
  resource is TuxGrid::Image
)
when {
  principal has strictPipeline && principal.strictPipeline &&
  (!(context has jenkinsfileApproved) || !context.jenkinsfileApproved)
};

// Runtime gate (catches what static analysis cannot): the Groovy sandbox interceptor
// (PlatformGroovyInterceptor) counts denied escape-primitive calls per build. Any blocked
// Groovy operation attempted by a strict pipeline => deny. context.sandboxViolationCount is
// set by the attest shim from the interceptor's groovy-calls.json artifact; has-guarded.
@reason("strict pipeline: blocked Groovy operations were attempted (sandbox interceptor denials > 0)")
forbid (
  principal is TuxGrid::Pipeline,
  action == TuxGrid::Action::"Attest",
  resource is TuxGrid::Image
)
when {
  principal has strictPipeline && principal.strictPipeline &&
  context has sandboxViolationCount && context.sandboxViolationCount > 0
};
