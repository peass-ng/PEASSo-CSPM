# Azure native-final source integration review

The v2 saved-pair audit qualified 124 Hardening check IDs against the exact
`a79ff6f9` snapshot. The integration branch retains every check source file at
the audited digest. Only `peaso/collectors/azure.py` differs from the worker's
source proof: the integrated collector adds read-only Exposure facts for
MySQL/Redis firewall child rules, App Service authentication, and Compute
Gallery detail. It does not remove or alter fields used by the selected
Hardening evaluators.

The v2 proof and pending manifest pin the integrated collector digest
`438bc588ecf626c0fa931114130a83397423adad4aa6cbf361f66def122915ff`.
The updated proof digest is
`f6d758fe5db67122c01422a043255d2b374da6be792c59f331d40f6a4f37eae7`.
Hosted qualification and runtime admission remain off pending the paired gate.
