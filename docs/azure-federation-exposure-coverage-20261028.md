# Azure multi-tenant app and federation exposure coverage

| Exposure primitive | Native decision | Test |
| --- | --- | --- |
| App sign-in audience admits other organizations or personal accounts | Conditional external-audience signal records the actual Graph value | `test_azure_application_external_sign_in_audience_is_conditional` |
| Foreign-owned service principal in the tenant | Outside ownership is flagged; associated federation remains conditional | `test_azure_foreign_application_is_external_and_federation_is_conditional` |
| Graph application federated identity credential | Collected credential reaches standalone native trust review | `test_collected_graph_app_federated_credential_reaches_native_exposure_review` |
| User-assigned managed identity federated credential | Child credential resolves to its actual ARM identity | `test_azure_managed_identity_federated_credentials_resolve_arm_parent` |
| Exact subject, audience and issuer tuple | Well-formed tuple requires manual issuer-ownership review; missing evidence is UNKNOWN | `test_exact_azure_federation_subject_needs_issuer_ownership_review` |
| Flexible claims expression and broad subject selectors | Supported immutable selectors receive MANUAL; broad Terraform wildcard is FAIL; unsupported or missing selectors are UNKNOWN | `test_azure_flexible_federation_expression_is_parsed_before_risk_decision`; `test_complete_federation_findings_graph_and_principals_match_literal_scan` |

Residual UNKNOWN/MANUAL handling: external issuer ownership, consent in another tenant, actual service-principal authorization, malformed or unsupported expressions and incomplete Graph reads are not inferred. A configured credential is a token-exchange capability, not proof that an external subject currently controls the issuer or has successfully exchanged a token.
