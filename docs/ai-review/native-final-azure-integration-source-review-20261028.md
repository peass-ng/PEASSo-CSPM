# Azure native-final source integration review

The v2 saved-pair audit qualified 124 Hardening check IDs against the exact
`a79ff6f9` snapshot. The integration branch retains every check source file at
the audited digest. Only `peaso/collectors/azure.py` differs from the worker's
source proof: the integrated collector adds read-only Exposure facts for
MySQL/Redis firewall child rules, App Service authentication, and Compute
Gallery detail. It does not remove or alter fields used by the selected
Hardening evaluators.

The v2 proof and pending manifest pin the integrated collector digest
`7817d5acf39fc9e9e6b9884370631956e5115ed1600faf48f915c9149fe5a9f0`.
The updated proof digest is
`daae57e77ad0a52bcd1b40ef886591728c1f149df008edc88267ec2ce5fd9685`.
Hosted qualification and runtime admission remain off pending the paired gate.
