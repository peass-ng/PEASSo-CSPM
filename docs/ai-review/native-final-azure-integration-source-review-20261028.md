# Azure native-final source integration review

The v2 saved-pair audit qualified 124 Hardening check IDs against the exact
`a79ff6f9` snapshot. The integration branch retains every check source file at
the audited digest. Only `peaso/collectors/azure.py` differs from the worker's
source proof: the integrated collector adds read-only Exposure facts for
MySQL/Redis firewall child rules, App Service authentication, and Compute
Gallery detail. It does not remove or alter fields used by the selected
Hardening evaluators.

The v2 proof and pending manifest pin the integrated collector digest
`485d5d6eeb1a24ca8975a919f74a6df80dbcdefb21530b795be7987697c3f99b`.
The updated proof digest is
`1d49f9a5cfab74f4265d5500e17f7f6dbacdc67f7b4fa39b332c7daee71169d0`.
Hosted qualification and runtime admission remain off pending the paired gate.
