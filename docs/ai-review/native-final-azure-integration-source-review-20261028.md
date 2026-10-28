# Azure native-final source integration review

The v2 saved-pair audit qualified 124 Hardening check IDs against the exact
`a79ff6f9` snapshot. The integration branch retains every check source file at
the audited digest. Only `peaso/collectors/azure.py` differs from the worker's
source proof: the integrated collector adds read-only Exposure facts for
MySQL/Redis firewall child rules, App Service authentication, and Compute
Gallery detail. It does not remove or alter fields used by the selected
Hardening evaluators.

The v2 proof and pending manifest pin the integrated collector digest
`e031abe7aeb40bdd394c1076d6cdd30feb8979a261053d78bea53c078ac75193`.
The updated proof digest is
`7da316ee3f1fb63965d2a092fc53455df48808f6ea43c4ddd55545880cc0556f`.
Hosted qualification and runtime admission remain off pending the paired gate.
