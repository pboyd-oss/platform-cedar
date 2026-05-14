permit (
  principal is TuxGrid::Pipeline,
  action == TuxGrid::Action::"Promote",
  resource is TuxGrid::Image
);

@reason("one or more required attestation types absent for production promotion")
forbid (
  principal is TuxGrid::Pipeline,
  action == TuxGrid::Action::"Promote",
  resource is TuxGrid::Image
)
when {
  context.targetTier == "production" &&
  !context.attestationTypes.containsAll([
    "https://tuxgrid.com/attestation/build/v1",
    "https://tuxgrid.com/attestation/tests/v1",
    "https://tuxgrid.com/attestation/scan/v1",
    "https://tuxgrid.com/attestation/pipeline/v1",
    "slsaprovenance1",
    "cyclonedx"
  ])
};

@reason("scan/v1 attestation is older than 24 hours")
forbid (
  principal is TuxGrid::Pipeline,
  action == TuxGrid::Action::"Promote",
  resource is TuxGrid::Image
)
when {
  context.targetTier == "production" &&
  context.scanAgeSeconds > 86400
};
