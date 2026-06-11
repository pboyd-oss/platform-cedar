// witness-dark.cedar
//
// Fail closed when the Tetragon eBPF witness produced ZERO exec events for a build that DID
// run under a valid PLATFORM_AUDIT_ID. execs==0 with a real auditId means the kernel-level
// witness was dark (e.g. the stale containerd-socket bind-mount bug) — the build's syscalls
// were never observed, so the "ran nothing else" half of the two-witness model is unproven.
// Gated on strictPipeline (opt-in enforce) per platform posture.
//
// context.tetragonExecsObserved = audit-service total_execs correlated to this auditId,
// forwarded by platform-attest-coordinator. has-guarded so non-Attest authorize calls and
// builds predating the field are unaffected.

@reason("strict pipeline: Tetragon witness was dark (0 execs observed) — build syscalls unverified")
forbid (
  principal is TuxGrid::Pipeline,
  action == TuxGrid::Action::"Attest",
  resource is TuxGrid::Image
)
when {
  principal has strictPipeline && principal.strictPipeline &&
  principal.hasAuditId &&
  context has tetragonExecsObserved && context.tetragonExecsObserved == 0
};

// The Groovy runtime tracer (PlatformGroovyRuntimeTracer) injects a ptRuntimeTrace() call
// before every top-level call statement; only the TRUSTED library sink actually emits the
// GROOVY_RUNTIME events the audit service counts. So 0 events for a real strict build means
// the tracer was disabled, bypassed, or its sink shadowed by a team no-op — deny.
// context.groovyRuntimeCalls = audit-service total_groovy_runtime_calls; has-guarded.
@reason("strict pipeline: Groovy runtime tracer produced 0 events — tracer off, bypassed, or shadowed")
forbid (
  principal is TuxGrid::Pipeline,
  action == TuxGrid::Action::"Attest",
  resource is TuxGrid::Image
)
when {
  principal has strictPipeline && principal.strictPipeline &&
  principal.hasAuditId &&
  context has groovyRuntimeCalls && context.groovyRuntimeCalls == 0
};
