# Azure native-final source integration review

The v2 saved-pair audit qualified 124 Hardening check IDs against the exact
`a79ff6f9` snapshot. The integration branch retains every check source file at
the audited digest. Only `peaso/collectors/azure.py` differs from the worker's
source proof: the integrated collector adds read-only Exposure facts for
MySQL/Redis firewall child rules, App Service authentication, and Compute
Gallery detail. It does not remove or alter fields used by the selected
Hardening evaluators.

The v2 proof and pending manifest pin the integrated collector digest
`d114c0e89dd59ebf881f51b1ead44aac19c7dc456dcad807debb29c23efe84dd`.
The updated proof digest is
`8790b14b533f7a466faa3df22c4846f27544f7ed5d082471b0e656e08f3da37a`.
Hosted qualification and runtime admission remain off pending the paired gate.
