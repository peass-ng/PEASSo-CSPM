# Azure native-final source integration review

The v2 saved-pair audit qualified 124 Hardening check IDs against the exact
`a79ff6f9` snapshot. The integration branch retains every check source file at
the audited digest. Only `peaso/collectors/azure.py` differs from the worker's
source proof: the integrated collector adds read-only Exposure facts for
MySQL/Redis firewall child rules, App Service authentication, and Compute
Gallery detail. It does not remove or alter fields used by the selected
Hardening evaluators.

The v2 proof and pending manifest pin the integrated collector digest
`5eb0bbe375f851c6e66b247bc6f49291f40a8079550538775780f28368bb5961`.
The updated proof digest is
`d643af7293d62e4c5e93cd82b0bd0d82f026747e83db3ff70890c09180225c95`.
Hosted qualification and runtime admission remain off pending the paired gate.
