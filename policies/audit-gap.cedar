permit (
  principal is TuxGrid::Team,
  action == TuxGrid::Action::"AuditCompliance",
  resource is TuxGrid::Pipeline
);

@reason("pipeline has never completed an attestation cycle")
forbid (
  principal is TuxGrid::Team,
  action == TuxGrid::Action::"AuditCompliance",
  resource is TuxGrid::Pipeline
)
when { context.lastAttestationAgeSeconds > 9223372036854775806 };

@reason("no attestation in 7 days — pipeline may be abandoned or broken")
forbid (
  principal is TuxGrid::Team,
  action == TuxGrid::Action::"AuditCompliance",
  resource is TuxGrid::Pipeline
)
when { context.lastAttestationAgeSeconds > 604800 };

@reason("pipeline has never produced a scan/v1 attestation")
forbid (
  principal is TuxGrid::Team,
  action == TuxGrid::Action::"AuditCompliance",
  resource is TuxGrid::Pipeline
)
when {
  !context.attestationTypes.contains("https://tuxgrid.com/attestation/scan/v1")
};
