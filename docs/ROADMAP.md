# Roadmap and open items

## Draft 0.8 (planned, after the first round of public feedback)

### Discovery and multiple Authorities

A thin RP package (script injector plus RPC client) on a tailnet-connected
machine discovers Authority nodes and assigns one per ceremony.

- **Authenticated discovery.** Accept only nodes carrying a dedicated tag (for
  example `tag:bytebind-authority`) whose `tagOwners` are locked down, and
  verify each candidate through `whois` and its `*.ts.net` certificate before
  use. A rogue node that passes discovery could grant anything, so this becomes
  a MUST.
- **Per ceremony, not per message.** `BEGIN`, `PROVE`, and `REDEEM` must all
  reach the Authority that created the transaction. `TRY`/`WHO` already carry
  the `authority` URL for the browser; the RP records which Authority issued
  each `cid` (or encodes it in the transaction handle) and sends `REDEEM` there.
- **One policy source.** Every Authority must read the same policy (ideally the
  tailnet policy file or app capabilities), or an attacker retries until a
  lenient node is chosen.
- **Randomness is availability, not security.** Random assignment spreads load
  and enables failover; the spec must not present it as a protection.
- **Implementation:** a selection layer in `AuthorityClient` (discovery,
  per-`cid` affinity, failover) and tests for a rogue node, a policy mismatch,
  and an Authority going down.

### Folding in feedback

Questions put to the Tailscale community:

- Are the LocalAPI `status`/`whois` fields used by the provider (`TailscaleIPs`,
  `ShareeNode`, `StableID`, `Tags`, `Sharer`) stable enough, or is there a
  supported alternative (for example `tsnet`'s client)?
- Would app capabilities in the policy file be a better authorization signal
  than tags?
- How does ByteBind compare with `tsidp` and `tailscale serve` identity headers?
- Has anyone hit Chrome's Local Network Access prompt with public sites calling
  `*.ts.net` addresses?

## Open questions

- **Tag semantics.** The spec does not yet say whether required tags mean "any
  of" or "all of". The implementation makes it a per-RP setting (default
  "any").
- **Specification license.** The spec text is copyright, all rights reserved,
  while the code is MIT and the name is open. Consider CC BY 4.0 for the spec;
  an IETF submission would bring its own terms.
- **Embedded provider.** A package built on `tsnet` could run the Authority
  in-process. Either keep the RP/Authority split inside the package (preferred)
  or add an "embedded provider" profile with an explicit trust argument.
- **Cloud provider profile.** What a managed provider must guarantee:
  authoritative connection-to-device mapping (no source NAT hiding the device),
  and signed `GRANT`s that RPs can verify offline.

## Verified so far

- 96 unit and integration tests, including hostile inputs, both control
  transports with real Unix-socket peer credentials, races, and clock skew.
- Clean install from the repository into a fresh virtual environment.
- A live run with real processes and headless Chromium: the session and
  transaction-bound profiles succeed end to end; a foreign origin and a device
  without the required tag are refused.

## Not yet verified

- The real `tailscaled` LocalAPI responses (the tests use recorded shapes).
- `tailscale cert` certificates and a real tailnet address on the attest listener.
- The HTTPS control channel between two real tailnet nodes.
- macOS and BSD peer credentials (`LOCAL_PEERCRED`); only Linux has run.
- Chrome's Local Network Access behavior for public pages calling tailnet addresses.
- An independent security review.
