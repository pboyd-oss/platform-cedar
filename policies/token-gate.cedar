permit (
  principal is TuxGrid::Team,
  action == TuxGrid::Action::"IssueCredentials",
  resource
);

@reason("scan/v1 attestation was not verified before credential issuance")
forbid (
  principal is TuxGrid::Team,
  action == TuxGrid::Action::"IssueCredentials",
  resource
)
unless { context.scanAttestationVerified };

@reason("production credentials require all four attestation types on the image")
forbid (
  principal is TuxGrid::Team,
  action == TuxGrid::Action::"IssueCredentials",
  resource
)
when {
  context.environment == "production" &&
  !context.attestationTypes.containsAll([
    "https://tuxgrid.com/attestation/build/v1",
    "https://tuxgrid.com/attestation/tests/v1",
    "https://tuxgrid.com/attestation/scan/v1",
    "https://tuxgrid.com/attestation/pipeline/v1"
  ])
};
