# ByteBind: making the private network part of the login

I wanted to protect the management interface of a public application that can control resources on my tailnet.

Putting the interface on the tailnet would have solved it. In this case, I wanted to keep the application's public origin and deployment, while requiring management access to come from an authorized tailnet device.

That became **ByteBind**: a browser completes an authentication exchange through both the public application and a private Authority. The Authority identifies the device making the private connection, checks whether it is allowed, and returns proof material that the browser carries back to the application.

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

The exchange establishes participation through an authorized private-network device. It does not identify the person using that device. Applications needing explicit human approval can add a user-authentication step.

An authorized device is a trust assumption. Compromising it, stealing the ceremony's secrets, or copying a valid session cookie weakens the guarantees. Short leases limit the useful lifetime of a copied session.

The intended experience is to open the management page and let the exchange happen in the background. Browser permission rules for public pages accessing private addresses may introduce a prompt; testing that behavior on a real tailnet remains on the roadmap.

## From TailBind to ByteBind

The early drafts were called **TailBind** because the first provider was Tailscale. The protocol's actual dependency is broader: an authenticated private path, a reliable mapping from the connection to a device, and an authorization policy.

I renamed it ByteBind in draft 0.6. The current specification is draft 0.7.

Its cryptography uses HMAC-SHA256, HKDF-SHA256, and AES-256-GCM. The design work is in connecting the channels, scoping the authorization, and consuming transactions safely.

The reference implementation has unit and integration coverage and has completed browser exchanges in the test setup. Real-tailnet identity and certificate behavior, cross-node control traffic, browser permissions, and independent security review remain outstanding. I am publishing the draft to get those assumptions examined.

Read the [technical companion](https://blog.bytes.coffee/2026/10/bytebind-under-the-hood/) for the endpoint flow and cryptographic transcripts, or the [draft 0.7 specification](https://blog.bytes.coffee/extra/bytebind-spec-0.7.md) and [roadmap snapshot](https://blog.bytes.coffee/extra/bytebind-roadmap.md) for the details and open questions.

This started with “how do I protect the management page for this server?” I am now considering an Internet-Draft as a way to get useful criticism of the answer.

Yet again, a problem created by [**Bad Decisions**](https://bytes.coffee/bad-decisions/web/) resulted in a **Good Decision**.

I may have to rename that project.

---

**ByteBind**  
© 2026 Bytes & Coffee Digital Studio
