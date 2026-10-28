# Azure Functions HTTP trigger source proof

The reviewed Azure collector changes from SHA-256
`b4aa1bb8dfde718bbcd2116f5de411d5554858271848af879aa0ff60b7b60f02`
to `b4aa1bb8dfde718bbcd2116f5de411d5554858271848af879aa0ff60b7b60f02`.
The source change schedules one paged `functions` LIST for each collected
Function app and deployment slot through the existing per-scan reader. It
derives Function app membership from the parent site's `kind`, validates each
FunctionEnvelope child ID and type, rejects duplicate IDs across pages, and
records read status on the parent or slot.

The [Microsoft Functions LIST API](https://learn.microsoft.com/en-us/rest/api/appservice/web-apps/list-functions?view=rest-appservice-2025-05-01)
documents the read-only collection and its `config`, `isDisabled`, files,
test data, and invocation URL fields. Only the HTTP trigger `authLevel`,
`methods`, `route`, disabled flag, and config-completeness flag enter the
snapshot. The collector drops source files, test data, connection names and
invocation URL templates; it never reads keys or function secrets. An absent
or malformed binding, missing auth level, disabled-state uncertainty, or
incomplete page remains unresolved in native assessment. The [Azure Functions HTTP trigger guide](https://learn.microsoft.com/en-us/azure/azure-functions/functions-bindings-http-webhook-trigger) defines `anonymous`, `function`, and `admin` authorization levels. An active `anonymous` HTTP trigger is distinct from one requiring a function or admin key; Easy Auth and site network restrictions remain separate gates.

`scripts/peaso_repin_sources.py` refreshed current-byte pins. The archived
epoch source and predecessor digests remain fixed. Focused transport tests
verify one parent and one slot LIST plus redaction of mock secret fields.
