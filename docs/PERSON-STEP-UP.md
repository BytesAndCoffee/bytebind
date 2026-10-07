# Authority-owned person step-up

The experimental implementation targets protocol v1, specification 0.8-draft.
Signed synthetic authenticators exercise the verifier. Real Chrome, Safari and
Firefox on private HTTPS, platform authenticators and security keys still need
acceptance testing; see [the release gates](ROADMAP.md). Recovery is disabled.

## Operator setup

Install `bytebind[person]` on the Authority. The verifier is pinned to
`fido2==2.2.1`; credentials use ES256 and discoverable registration with user
verification. Add a separate private HTTPS listener to the Authority configuration:

```toml
[person]
origin = "https://authority.example-tailnet.ts.net:8444"
enrollment_tags = ["tag:bytebind-enrollment"]
self_enrollment = false
```

The person origin must differ from `authority.attest_url`. Use canonical origins:
no trailing slash or explicit default `:443`. Serve it directly on the private
overlay with a certificate for that hostname, alongside the base and control
listeners:

```sh
bytebind-authority --config authority.toml person --host 100.64.0.10 --port 8444 --certfile cert.pem --keyfile key.pem
```

For each participating `[[rp]]`, opt into person assurance and choose the maximum
age. Identity disclosure is separately permitted:

```toml
assurances = ["device", "presence", "verification"]
person_max_age = 600
claims = ["device_id", "person_subject"]
allow_self_enrolled = false
```

Keep the RP's existing device policy. Permit those devices to reach both private
listeners. Enrollment and management additionally require every configured
`enrollment_tags` tag. Operators assign device tags; application developers
choose route requirements. Provider accounts and device owners never become
person subjects.

Create a new independently named subject using the Authority's local operator
command:

```sh
bytebind-authority --config authority.toml invite --name "Alice"
```

Deliver the one-use invite to its intended person through your trusted channel.
It expires after 15 minutes. On an enrollment-authorized device, open
`https://authority.example-tailnet.ts.net:8444/enroll`, enter the invite and a
credential label, prepare registration, then click the registration button.
The `/manage` page requires a fresh verified passkey before listing, renaming,
revoking or adding credentials. A shared device can enroll and authenticate
different subjects; a subject can attach credentials on multiple devices.

## Application bindings

Both FastAPI and Flask accept these binding options:

```python
@app.get("/account")
@bind(assurance="verification", person_max_age=300, identify=True)
def account(lease=bind.lease):
    return {"person": lease.claims["person_subject"]}

@app.post("/approve")
@bind(grant=bind.TRANSACTION, assurance="verification")
def approve(grant=bind.grant):
    return {"approved": True}
```

`presence` requires user presence; `verification` requires user presence and user
verification. `identify=True` requests an RP-pairwise `person_subject` and needs
the Authority registration's matching claim permission. No credential IDs or
provider-owner identity reach the application. Route `require=[...]` still
checks all supplied device tags or authorization claims.

The built-in HTML authentication page selects person assurance from the protected
route. A custom page can call `ByteBind.personSession("/account")`; the RP selects
the stored route policy, so the browser cannot lower its assurance requirement.
Base attestation runs first. The Authority's per-RP iframe then prepares passkey
options and invokes WebAuthn directly from the user's click. It sends no messages,
identity, attestation proof or H2 to the application page. The original client
collects H2 through the base listener and submits the ordinary RP proof.

## Sessions and API clients

Device-only renewal preserves the browser lease's person association without
refreshing its original age or deadline. Each call to a person-gated endpoint
validates the association with the Authority before its handler runs. Expired
evidence, revoked credentials, suspended subjects or lost device continuity
require fresh step-up. An Authority outage refuses the person-gated call.
Transaction-bound person operations always require a fresh assertion.

App-facing lease objects contain claims and assurance, without internal
association handles, device-grant references or lease deadlines. A headless
Python or requests client encountering person step-up raises `StepUpRequired`;
it does not open a browser, disclose handoff tokens or retry the protected
operation. Device-only API use continues through the existing client.

Existing draft-0.7 pending transactions cannot resume after the schema upgrade.
Old transaction rows are retained separately as `transactions_v07`; begin a new
ceremony. The Authority database contains credential and subject state and must
remain owned and writable only by the Authority service account.
