# ByteBind overview

ByteBind authorizes public management access through a fresh exchange involving
an allowed private-network device. The browser obtains a challenge from the
application, contacts a private Authority, and returns a proof that the
application redeems before granting access.

## Request flow

1. The browser requests a management lease or submits a protected operation.
2. The application creates a transaction with the Authority over an authenticated
   control channel and returns its challenge to the browser.
3. The browser posts a challenge MAC to the Authority's private `/attest`
   endpoint. The Authority identifies the connecting device and checks policy.
4. The Authority returns an encrypted secret. The browser uses it to compute a
   redemption MAC and submits that proof to the application.
5. The application redeems the proof with the Authority, which consumes the
   transaction and returns a scoped grant.

The **session profile** creates a short lease, renewed by further exchanges.
When private access is lost, renewals fail and the last lease expires. The
**transaction-bound profile** includes a digest of a submitted operation and
authorizes only that stored request.

The proofs use HMAC-SHA256, the response key uses HKDF-SHA256, and the private
response uses AES-256-GCM. Overlay identity and policy supply device authorization;
the cryptographic transcript connects that decision to the public transaction.

The design assumes trusted application code and an uncompromised authorized
device. A valid session cookie remains usable until server-side expiry.
Independent security review and real-tailnet deployment checks remain open.

See [SPEC.md](../SPEC.md) for fields and validation rules,
[ROADMAP.md](ROADMAP.md) for verification status, and
[blog-post.md](blog-post.md) for the motivation.
