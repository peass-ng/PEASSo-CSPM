# Azure ML online scoring authentication evidence

The existing paged online-endpoint LIST uses ARM API `2024-04-01`; the
[online endpoint schema](https://learn.microsoft.com/en-us/azure/templates/microsoft.machinelearningservices/2024-04-01/workspaces/onlineendpoints)
includes `properties.authMode` with `Key`, `AMLToken`, and `AADToken`. The
collector already retains that field in its metadata-only response. This
change makes no new read and needs no collector source re-pin.

Microsoft's [online endpoint authentication guide](https://learn.microsoft.com/en-us/azure/machine-learning/how-to-authenticate-online-endpoint?view=azureml-api-2)
distinguishes static endpoint keys, Azure ML tokens, and Entra tokens. Entra
scoring requires a role with `score/action`; possession of a key or AML token
authorizes the other modes. Native evidence now records the mode for an
observed public scoring endpoint, including a selected-IP endpoint lingering
after the workspace public gate is disabled. Missing or unfamiliar modes are
identified as unresolved without changing the network verdict. The scan does
not claim to know key or token recipients. Tests use local snapshots; no cloud
access or credential retrieval occurs.
