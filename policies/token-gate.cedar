// Base permit for credential issuance.
// Forbid rules can be added here without a code change — pure ConfigMap update.
permit (
  principal is TuxGrid::Team,
  action == TuxGrid::Action::"IssueCredentials",
  resource
);
