# ByteBind overview

ByteBind authorizes public management access through a fresh exchange involving
an allowed private-network device. The browser obtains a challenge from the
application, contacts a private Authority, and returns a proof that the
application redeems before granting access.

## Request flow

1. The browser requests a management lease or submits a protected operation.
2. The application creates a transaction with the Authority over an authenticated
   control channel and returns its challenge to the browser.
3. The browser posts a challenge MAC to the Authority's private `/attestation`
   endpoint. The Authority identifies the connecting device and checks policy.
4. For a person-required route, base acceptance returns a one-use handoff.
   The browser embeds an invisible private Authority frame, which invokes the
   browser's native passkey prompt. The client collects the result through
   `/attestation/result` after the assertion succeeds.
   Device-only routes receive the result directly from `/attestation`.
5. The Authority returns an encrypted secret. The browser uses it to compute a
   redemption MAC and submits that proof to the application.
6. The application redeems the proof with the Authority, which consumes the
   transaction and returns a scoped grant.

The **session profile** creates a short lease, renewed by further exchanges.
When private access is lost, renewals fail and the last lease expires. The
**transaction-bound profile** includes a digest of a submitted operation and
authorizes only that stored request.

Optional `presence` and `verification` assurance use Authority-owned WebAuthn
credentials. Person identity is independent of provider accounts and device
ownership. Person session age never resets during device renewal; the application
validates the association before each person-gated handler. A person-required
transaction always needs a fresh assertion. Passkey registration and management
happen on a separate private Authority listener.

The proofs use HMAC-SHA256, the response key uses HKDF-SHA256, and the private
response uses AES-256-GCM. Overlay identity and policy supply device authorization;
the cryptographic transcript connects that decision to the public transaction.

The design assumes trusted application code and an uncompromised authorized
device. A valid session cookie remains usable until server-side expiry.
Independent security review and real-tailnet deployment checks remain open.

See [SPEC.md](../SPEC.md) for fields and validation rules,
[ROADMAP.md](ROADMAP.md) for verification status,
[THREAT-MODEL.md](THREAT-MODEL.md) for threats and open risks,
[PERSON-STEP-UP.md](PERSON-STEP-UP.md) for passkey setup, and
[blog-post.md](blog-post.md) for the motivation.
