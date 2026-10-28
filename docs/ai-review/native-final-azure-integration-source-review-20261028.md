# Azure native-final source integration review

The v2 saved-pair audit qualified 124 Hardening check IDs against the exact
`a79ff6f9` snapshot. The integration branch retains every check source file at
the audited digest. Only `peaso/collectors/azure.py` differs from the worker's
source proof: the integrated collector adds read-only Exposure facts for
MySQL/Redis firewall child rules, App Service authentication, and Compute
Gallery detail. It does not remove or alter fields used by the selected
Hardening evaluators.

The v2 proof and pending manifest pin the integrated collector digest
`ba4b8bc54cdcbb1e35ef50a7dea9d04928a6fe5ed6ca885e4722ec1c8e750d67`.
The updated proof digest is
`3048285a3e2c832171538ead574fe6df915e54f9b0875a7458210f3365178c0a`.
Hosted qualification and runtime admission remain off pending the paired gate.
