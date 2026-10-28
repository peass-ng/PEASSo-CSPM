# NGINX for Azure exposure source proof

The [deployment ARM resource](https://learn.microsoft.com/en-us/azure/templates/nginx.nginxplus/2025-11-01/nginxdeployments) provides `networkProfile.frontEndIPConfiguration.publicIPAddresses`. An attached public IP is the public frontend; a private-only deployment has no public IP in that list. The existing Azure public-IP inventory supplies the assigned address when available.

The [configuration ARM resource](https://learn.microsoft.com/en-us/azure/templates/nginx.nginxplus/2025-11-01/nginxdeployments/configurations) has `rootFile`, base64 `files[].content`, and optionally an opaque package. The collector uses read-only paged configuration LIST and detail GET only when LIST omits files. It resolves includes among returned files and stores only transport/port pairs. Configuration contents, including possible credentials, are never copied to the snapshot. Missing includes, opaque packages, and nonliteral listen ports yield UNKNOWN rather than an inferred closed listener.

The focused test feeds a public frontend with a configured TCP 8443 listener and a synthetic secret, a private frontend, an opaque package, and a missing include. It checks findings, no duplicate NGINX read, and no secret in the saved snapshot. No cloud resource was changed.
