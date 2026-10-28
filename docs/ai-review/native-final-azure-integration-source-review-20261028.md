# Azure native-final source integration review

The v2 saved-pair audit qualified 124 Hardening check IDs against the exact
`a79ff6f9` snapshot. The integration branch retains every check source file at
the audited digest. Only `peaso/collectors/azure.py` differs from the worker's
source proof: the integrated collector adds read-only Exposure facts for
MySQL/Redis firewall child rules, App Service authentication, and Compute
Gallery detail. It does not remove or alter fields used by the selected
Hardening evaluators.

The v2 proof and pending manifest pin the integrated collector digest
`cd4bab2ab681a14385a95d68bd5c48e5222ce1bb8c2eb8db7f4ce2c7f35861a9`.
The updated proof digest is
`2d421f313ee33c367c2d1f9ac64d55ebf85a31167dee592514436e1654b9b366`.
Hosted qualification and runtime admission remain off pending the paired gate.
