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
