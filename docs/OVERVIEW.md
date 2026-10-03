# ByteBind in one paragraph

The browser has to complete a round trip over the private network in the middle
of the login, so the app grants access only while you are actually on that
network, on an allowed device.

## The longer version

The client asks the app for a protected endpoint. The app asks the auth
provider (the Authority) to open a transaction; the Authority mints secrets and
a challenge, and gives the app a scoped auth set, which passes the challenge on
to the client. The client then contacts the Authority directly over the private
network, sending a proof (an HMAC keyed by the challenge, over a fresh nonce).
The Authority checks that proof, identifies the device from its private-network
identity (with Tailscale: `whois` and tags), and replies over the private
network with a secret encrypted so only the challenge holder can open it. The
client uses that secret to compute a final proof and hands it to the app. The
app redeems it with the Authority, which checks it, consumes the transaction,
and returns a grant. Only then does the app approve the request.

Nothing in ByteBind is a signature: the proofs are HMACs, and the Authority's
reply is AES-256-GCM encryption. See [SPEC.md](../SPEC.md) for the exact
transcripts and [blog-post.md](blog-post.md) for the motivation.
