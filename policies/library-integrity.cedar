// library-integrity.cedar
//
// OPT-IN strict tier. Denies Attest when a trusted library's ACTUALLY-LOADED code does not
// match the platform's expected (pinned) digest — independent of the version the build
// self-reports. This closes the gap where hasUnpinnedLibraries only checks that the
// DECLARED version is a 40-hex SHA (the build's own word): here the audit-service hashes the
// library code that really loaded on disk (LibrarySource.loadedDigest, set by
// PlatformAuditGraphListener) and the coordinator compares it against a platform-controlled
// expected-digest registry (a GitOps ConfigMap, which a build cannot influence).
//
// context.libraryDigestMismatchCount = number of loaded libraries that have an expected
// digest configured but whose observed loaded-code digest is absent or different. Computed
// by the coordinator; 0 when the registry is unconfigured (gate off) or every pinned library
// matched. has-guarded + gated on principal.strictPipeline, so non-strict pipelines and
// Promote/other Pipeline-principal calls are unaffected.
//
// Fail-closed: a pinned library that loaded but produced NO observed digest counts as a
// mismatch (you cannot prove it is the approved code).

@reason("strict pipeline: a trusted library's loaded code does not match its expected pinned digest")
forbid (
  principal is TuxGrid::Pipeline,
  action == TuxGrid::Action::"Attest",
  resource is TuxGrid::Image
)
when {
  principal has strictPipeline && principal.strictPipeline &&
  context has libraryDigestMismatchCount && context.libraryDigestMismatchCount > 0
};