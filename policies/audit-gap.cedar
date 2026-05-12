permit (
  principal is TuxGrid::Team,
  action == TuxGrid::Action::"AuditCompliance",
  resource is TuxGrid::Pipeline
);

// Pipeline has never produced any attestation (Long.MAX sentinel)
forbid (
  principal is TuxGrid::Team,
  action == TuxGrid::Action::"AuditCompliance",
  resource is TuxGrid::Pipeline
)
when { context.lastAttestationAgeSeconds > 9223372036854775806 }
annotations { "reason": "pipeline has never completed an attestation cycle" };

// No attestation in 7 days
forbid (
  principal is TuxGrid::Team,
  action == TuxGrid::Action::"AuditCompliance",
  resource is TuxGrid::Pipeline
)
when { context.lastAttestationAgeSeconds > 604800 }
annotations { "reason": "no attestation in 7 days — pipeline may be abandoned or broken" };

// Pipeline has never produced a scan/v1 attestation
forbid (
  principal is TuxGrid::Team,
  action == TuxGrid::Action::"AuditCompliance",
  resource is TuxGrid::Pipeline
)
when {
  !context.attestationTypes.contains("https://tuxgrid.com/attestation/scan/v1")
}
annotations { "reason": "pipeline has never produced a scan/v1 attestation" };
