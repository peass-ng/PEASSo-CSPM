# Azure native-final source integration review

The v2 saved-pair audit qualified 124 Hardening check IDs against the exact
`a79ff6f9` snapshot. The integration branch retains every check source file at
the audited digest. Only `peaso/collectors/azure.py` differs from the worker's
source proof: the integrated collector adds read-only Exposure facts for
MySQL/Redis firewall child rules, App Service authentication, and Compute
Gallery detail. It does not remove or alter fields used by the selected
Hardening evaluators.

The v2 proof and pending manifest pin the integrated collector digest
`62edc021d6233f8c3dc066e8f4780fcd612cbcb60295f6f8af310bf72dbaf6b9`.
The updated proof digest is
`723740ed10a372ccad0f58306e940e88c781253438aff694c179186eba0e77e4`.
Hosted qualification and runtime admission remain off pending the paired gate.
