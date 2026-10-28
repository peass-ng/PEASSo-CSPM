# Azure native-final source integration review

The v2 saved-pair audit qualified 124 Hardening check IDs against the exact
`a79ff6f9` snapshot. The integration branch retains every check source file at
the audited digest. Only `peaso/collectors/azure.py` differs from the worker's
source proof: the integrated collector adds read-only Exposure facts for
MySQL/Redis firewall child rules, App Service authentication, and Compute
Gallery detail. It does not remove or alter fields used by the selected
Hardening evaluators.

The v2 proof and pending manifest pin the integrated collector digest
`ffa694575eba7314d4da2951ee642f125558da8ee87fd09c7ed74befeef96a44`.
The updated proof digest is
`6a7defde10f7fffc3ece8652614d2a76da32c7b938d0eef7ffaf4da49ea657b9`.
Hosted qualification and runtime admission remain off pending the paired gate.
