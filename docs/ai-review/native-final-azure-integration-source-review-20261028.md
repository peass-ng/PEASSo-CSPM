# Azure native-final source integration review

The v2 saved-pair audit qualified 124 Hardening check IDs against the exact
`a79ff6f9` snapshot. The integration branch retains every check source file at
the audited digest. Only `peaso/collectors/azure.py` differs from the worker's
source proof: the integrated collector adds read-only Exposure facts for
MySQL/Redis firewall child rules, App Service authentication, and Compute
Gallery detail. It does not remove or alter fields used by the selected
Hardening evaluators.

The v2 proof and pending manifest pin the integrated collector digest
`4ae95e535801cc62f2ee08015bfd6458957cf0247f40a8fb9a153b9949cf623c`.
The updated proof digest is
`a26f4bb9c0da2c28e6ed9c960349ca0955e27256cff39cb744ed42c94473c97a`.
Hosted qualification and runtime admission remain off pending the paired gate.
