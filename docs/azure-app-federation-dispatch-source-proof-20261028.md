# Azure application federation finding dispatch (2026-10-28)

The existing Microsoft Graph app credential collector writes `directory_federated_credential` rows from the app's federated identity credential LIST. The native `federated_findings` dispatcher previously recognized `directory_application_federated_credential`, so the collected Graph rows could appear in principal exposure but never produce a standalone `analysis.federated_trust` finding. This change adds the actual collected type to the dispatcher and retains the older alias. It performs no additional cloud read and does not change the trust classifier.

The [Microsoft Graph federated credential schema](https://learn.microsoft.com/en-us/graph/api/resources/federatedidentitycredential?view=graph-rest-1.0) describes the collected issuer, subject, and audience as token-exchange trust selectors. A focused test uses the collector's exact row type and verifies that a native federation review is emitted.

Current exposure analyzer SHA-256: `8263329b85e01375f2b693f71c5e886b6827c866e656b8571fc99af3138e11c3`.
