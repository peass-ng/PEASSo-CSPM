# Azure Functions HTTP trigger source proof

The [Microsoft Functions LIST API](https://learn.microsoft.com/en-us/rest/api/appservice/web-apps/list-functions?view=rest-appservice-2025-05-01) exposes read-only FunctionEnvelope metadata, including trigger configuration and disabled state. The collector schedules one paged `functions` LIST for each observed Function app and slot through the existing per-scan reader. It validates the child ID and type and rejects duplicate IDs. Only HTTP `authLevel`, methods, route, disabled state, and configuration completeness enter the snapshot; files, test data, connection names, invocation URL templates, and key material are discarded.

The [Azure Functions HTTP trigger guide](https://learn.microsoft.com/en-us/azure/azure-functions/functions-bindings-http-webhook-trigger) defines `anonymous`, `function`, and `admin` authorization levels. Native analysis records anonymous, key-required, disabled/no-HTTP, and unresolved trigger states alongside the separate public network and App Service authentication gates. Denied or incomplete LISTs, malformed children, missing auth levels, and unknown disabled state remain unresolved.

Current SHA-256: Azure collector `e6739b54f408957f1504a9fa7d2014fce9cae90d09be7ccafb5574fee1c81110`; internet exposure analyzer `8263329b85e01375f2b693f71c5e886b6827c866e656b8571fc99af3138e11c3`.
