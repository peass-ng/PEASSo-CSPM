# Azure native-final source integration review

The v2 saved-pair audit qualified 124 Hardening check IDs against the exact
`a79ff6f9` snapshot. The integration branch retains every check source file at
the audited digest. Only `peaso/collectors/azure.py` differs from the worker's
source proof: the integrated collector adds read-only Exposure facts for
MySQL/Redis firewall child rules, App Service authentication, and Compute
Gallery detail. It does not remove or alter fields used by the selected
Hardening evaluators.

The v2 proof and pending manifest pin the integrated collector digest
`fc248afe7f38f64d70c765fa97c845e6d879a7072fdac56abaacbfad76792090`.
The updated proof digest is
`e5561ba42283f377a629258a3831adc31e31dd85797fdaab4460f99b01b36a42`.
Hosted qualification and runtime admission remain off pending the paired gate.
