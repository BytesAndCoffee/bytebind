# ByteBind: making the private network part of the login

I wanted to protect the management interface of a public application that can control resources on my tailnet.

Putting the interface on the tailnet would have solved it. In this case, I wanted to keep the application's public origin and deployment, while requiring management access to come from an authorized tailnet device.

That became **ByteBind**: a browser completes an authentication exchange through both the public application and a private Authority. The Authority identifies the device making the private connection, checks whether it is allowed, and returns proof material that the browser carries back to the application.

**ByteBind isn’t a nicer login screen. It’s *no login screen*.**

No registration ceremony. No OIDC/OAuth ceremony. No redirects, PINs, keys, or account pickers.

For the developer, it’s an import, an app bind, and route binds. For the operator, it’s a few lines of policy. For the user, it’s seamless, ambient authentication.

**The developer declares what’s protected. The operator declares who’s trusted. The user just opens the page.**

That is the device-only flow. Some routes also need a person to participate.
Specification 0.8 adds optional Authority-owned passkeys for those routes, with
enrollment and an explicit presence or verification gesture.

<video controls preload="metadata" playsinline poster="https://blog.bytes.coffee/media/bytebind-explainer-0097862c.jpg" style="width:100%;border-radius:12px" aria-label="ByteBind explainer video">
  <source src="https://blog.bytes.coffee/media/bytebind-explainer-0097862c.mp4" type="video/mp4">
  <a href="https://blog.bytes.coffee/media/bytebind-explainer-0097862c.mp4">Download the ByteBind explainer.</a>
</video>

## How the exchange works

The public application asks the Authority to create a short-lived transaction. It passes a challenge to the browser, which uses it to contact the Authority over the private network.

The Authority identifies the connecting device through the overlay and applies the application's authorization policy. If the device is allowed, it returns an encrypted response containing a second secret. The browser uses that secret to produce a redemption proof and sends the proof to the public application.

The application redeems it with the Authority. Successful redemption consumes the transaction and returns the authorization result. The application can then issue a management session or perform the requested operation.

This separates the responsibilities cleanly. The application serves its normal public interface. The Authority handles private-network identity and policy. The browser must reach both during the same exchange.

## What access depends on

A private address alone is insufficient. The Authority needs an authenticated connection-to-device mapping and an explicit policy allowing that device to manage the application.

With Tailscale, the provider uses node identity and policy such as required tags or an allowlist. The Authority can return only the claims the application needs, keeping the rest of the device metadata within the private identity service.

The browser's origin also matters. A website open on an authorized laptop should not be able to borrow that laptop's network access to authenticate another application. The Authority checks the origin bound to each transaction, and the application checks its own authentication endpoints.

## Sessions and individual operations

ByteBind has two profiles.

The **session profile** issues a short management lease. The draft recommends three minutes, renewed every minute through another private-network exchange. Leaving the network stops successful renewals; access ends when the existing lease expires. This gives a bounded delay between losing network access and losing management access.

The **transaction-bound profile** covers one operation. The browser and application compute a digest of the request, which becomes part of the proof. The application stores that request and executes it only after successful redemption. This is useful for actions such as restarting a service or rotating a credential.

The application still owns execution and recovery. If a response is lost after an operation runs, obtaining fresh authorization must not accidentally repeat the operation.

## What the device proves

The base exchange establishes participation through an authorized private-network
device. It does not identify the person using that device. An application can
require `presence` or `verification` assurance in its route binding. Base
attestation still runs first; the private Authority then collects a passkey
assertion in an invisible iframe before releasing the proof material. The frame
opens the browser's native passkey prompt directly; it adds no panel to the
application page. Enrollment and passkey management use separate top-level
Authority pages. An operator's one-use enrollment invite is eight hex characters
and expires after 15 minutes, with persistent limits on failed guesses.

The Authority owns person subjects and passkey registration. A device's provider
account or owner never supplies the current person identity. Shared devices and
tagged service devices can therefore establish an independent human subject.
Applications can receive a pairwise person identifier when the operator permits
it. The iframe sends no identity or proof to the application page; claims arrive
only through authenticated redemption.

A person-verified session retains its original verification age while device
leases renew. Each person-gated endpoint validates the association before its
handler runs. A person-gated transaction requires a new assertion for that exact
operation. Neither a passkey nor the device exchange proves that the person
understood or intended the operation.

An authorized device is a trust assumption. Compromising it, stealing the ceremony's secrets, or copying a valid session cookie weakens the guarantees. Short leases limit the useful lifetime of a copied session.

The intended experience is to open the management page and let the exchange happen in the background. Browser permission rules for public pages accessing private addresses may introduce a prompt; testing that behavior on a real tailnet remains on the roadmap.

## How ByteBind differs from OIDC, and where tsidp fits

OpenID Connect gives applications a standard way to accept identity from a trusted provider. In the familiar authorization-code flow, the browser visits that provider, the application exchanges a code, and an ID token communicates the authentication result. OIDC itself doesn’t require passwords or a visible login screen. [OpenID Connect specification](https://openid.net/specs/openid-connect-core-1_0.html).

ByteBind addresses a narrower requirement: a public application needs fresh
participation through an authorized private-network device before granting
management access. Its device-only exchange happens in the background, without
an OIDC redirect. The result authorizes a short lease or one specific request.
Person-gated routes add an Authority-owned passkey assertion while retaining
the same device and transaction binding.

[tsidp](https://tailscale.com/docs/features/tsidp) turns Tailscale identity into standard OIDC/OAuth credentials for applications that already support those protocols. It can eliminate authentication prompts too. Its value is compatibility with existing applications and their identity integrations.

ByteBind’s focus is direct route protection, repeated private-network attestation, and transaction-bound authorization in applications adopting its bindings. Both aim to let users open an application without entering another password, but the integration and authorization model differ.

An application could use tsidp for its user identity and require ByteBind for a
privileged operation. Specification 0.8 defers OIDC/SAML integration; the
reference implementation provides no OIDC bridge or tsidp integration.

## From TailBind to ByteBind

The early drafts were called **TailBind** because the first provider was Tailscale. The protocol's actual dependency is broader: an authenticated private path, a reliable mapping from the connection to a device, and an authorization policy.

I renamed it ByteBind in draft 0.6. The current specification is 0.8-draft,
still protocol v1. Nothing has reached a stable release.

Its cryptography uses HMAC-SHA256, HKDF-SHA256, and AES-256-GCM. The design work is in connecting the channels, scoping the authorization, and consuming transactions safely.

The experimental implementation has unit and integration coverage, including
signed synthetic passkey assertions and both session and transaction flows.
The recorded suite through `c1f6e88` has 260 passing tests. A headless Chrome
test on loopback HTTPS also completed passkey registration and invisible-frame
step-up with a virtual authenticator. That checks the browser API and exchange,
while acceptance with real platform authenticators, Safari and Firefox,
local-network permissions, cross-node control traffic, and independent security
review remain open. The roadmap records those gates and the implementation
findings from agent review. I am publishing the draft to get those assumptions examined.

Read the [technical companion](https://blog.bytes.coffee/2026/10/bytebind-under-the-hood/)
for the original device exchange, the [current specification](https://github.com/BytesAndCoffee/bytebind/blob/main/SPEC.md)
and [roadmap](https://github.com/BytesAndCoffee/bytebind/blob/main/docs/ROADMAP.md)
for the protocol and open questions, or the [person setup guide](https://github.com/BytesAndCoffee/bytebind/blob/main/docs/PERSON-STEP-UP.md)
for passkey registration and route bindings. The published
[draft 0.7 snapshot](https://blog.bytes.coffee/extra/bytebind-spec-0.7.md) remains historical.

This started with “how do I protect the management page for this server?” I am now considering an Internet-Draft as a way to get useful criticism of the answer.

Yet again, a problem created by [**Bad Decisions**](https://bytes.coffee/bad-decisions/web/) resulted in a **Good Decision**.

I may have to rename that project.

---

**ByteBind**  
© 2026 Bytes & Coffee Digital Studio
