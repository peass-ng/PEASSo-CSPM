# Azure native-final source integration review

The v2 saved-pair audit qualified 124 Hardening check IDs against the exact
`a79ff6f9` snapshot. The integration branch retains every check source file at
the audited digest. Only `peaso/collectors/azure.py` differs from the worker's
source proof: the integrated collector adds read-only Exposure facts for
MySQL/Redis firewall child rules, App Service authentication, and Compute
Gallery detail. It does not remove or alter fields used by the selected
Hardening evaluators.

The v2 proof and pending manifest pin the integrated collector digest
`b4aa1bb8dfde718bbcd2116f5de411d5554858271848af879aa0ff60b7b60f02`.
The updated proof digest is
`2233a039a437c8506e14b86cdb8867541080cde613316a799fd239620f41e268`.
Hosted qualification and runtime admission remain off pending the paired gate.
