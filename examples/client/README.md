# Calling a ByteBind-protected API

[api.py](api.py) shows both profiles against the [example app](../rp_app.py):

- `api.get("/status")` uses a session lease, established and renewed by the client.
- `api.transaction("/restart", json={"service": "demo"})` approves one exact request.

Those two routes remain device-only. The same app also has `/verified` and
`/restart-verified` for browser passkey step-up, with registration links at
`/passkeys`. Calling a person-required route from this headless client raises
`bytebind.requests.StepUpRequired`; it carries no handoff token or URL and does
not open a browser, weaken assurance or retry the operation.

The client is a `requests.Session` subclass and returns ordinary
`requests.Response` objects.

Install `bytebind[requests]` (or `pip install '.[requests]'` from this checkout),
replace the HTTPS origin in the file, and run it from an authorized tailnet device.
The API and Authority must already be configured; the device must satisfy the
Authority's policy and reach its private attestation listener.

The example app's `/restart` handler returns JSON and increments a counter;
it does not restart a system service. Calls are never automatically retried.
