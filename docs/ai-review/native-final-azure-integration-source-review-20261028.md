# Azure native-final source integration review

The v2 saved-pair audit qualified 124 Hardening check IDs against the exact
`a79ff6f9` snapshot. The integration branch retains every check source file at
the audited digest. Only `peaso/collectors/azure.py` differs from the worker's
source proof: the integrated collector adds read-only Exposure facts for
MySQL/Redis firewall child rules, App Service authentication, and Compute
Gallery detail. It does not remove or alter fields used by the selected
Hardening evaluators.

The v2 proof and pending manifest pin the integrated collector digest
`bdae6e6a776990010634af7fb5e64633426a005bded7f61709f943b8a7f3d443`.
The updated proof digest is
`a975717776ff46a8cceabd3479a3d427ca798faedf4f5ce6bbf4ab97571daaf0`.
Hosted qualification and runtime admission remain off pending the paired gate.
