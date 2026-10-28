# Kubernetes Exposure B: invalid source ranges

The native Internet exposure path now keeps Service LoadBalancer and Ingress source-range declarations `UNKNOWN` when any listed range cannot be parsed as an IP network or an explicit public wildcard. A malformed annotation previously looked like a private allowlist and could mark a public frontend `PASS` without evidence that the controller enforced that restriction.

| Vector | Before | After | Evidence limit |
| --- | --- | --- | --- |
| Service LoadBalancer source ranges | An invalid value could block the path. | The invalid value is recorded and the path stays `UNKNOWN`. | The Kubernetes API does not show how a cloud load balancer controller handles the invalid value. |
| Ingress source-range annotation | An invalid value could block the path. | The invalid value is recorded and the path stays `UNKNOWN`. | The Ingress controller's acceptance and routing are not observed. |

The existing valid private-range block, public-range candidate, and explicit wildcard behavior are preserved. Both new UNKNOWN findings have four connected observed-evidence lines that start with the recorded value and name the possible effect and data impact. The original K8s audit's remaining externally determined vectors remain `IMPOSSIBLE-FROM-API`; this slice adds no live reachability claim.

Focused local suite: `tests/test_peaso_analysis_internet_exposure.py -k k8s` and `tests/test_peaso_k8s_principal_exposure.py`, with plugin autoload disabled and no repository conftest, 36 passed and 131 deselected. No cloud scan or model call was made.
