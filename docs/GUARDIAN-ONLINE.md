# Frequency Guardian v0.5.0 online prototype

This adds HTTPS delivery to the independently verified offline authority. The
phone polls every 15 seconds while the app is visible. It shows the authority's
signed Who / What / Target text, expiry, nonce and digest, then offers Approve and
Deny. Both decisions use the original attested candidate P-256 key. Neither tap
asks for biometrics or a password. Anyone controlling this unlocked phone can
approve. A decision is not confirmed until the authenticated server reports that
it durably recorded that exact decision. Nothing here executes an action.

There is no FCM, background service, telemetry, analytics or third-party model.
The authority's existing live Android certificate-status check remains necessary;
that external HTTPS check is security validation, not app telemetry. Leave the app
open to receive requests. Closing/backgrounding cancels unresolved review.

## Operator setup, in order

All paths and capitalized values below are operator-supplied placeholders. There
are no supplied deployment domains, TLS credentials, attestation pins or pairing
tokens. Use a separate verifier machine and persistent private disk for authority
state. `/dev/shm` is appropriate only for build/test intermediates, not deployment
state. Do not expose the development server on an untrusted network yet.

1. Build the verifier and Android APK as described in
   [GUARDIAN-OFFLINE.md](GUARDIAN-OFFLINE.md). Obtain the root pin, APK signer pin
   and patch policy independently. Initialize the authority using that guide.
   Protect its directory with mode 0700 and its files with mode 0600. Keep private
   policy, key, ledger and issued challenges together under independent custody.
2. Run `guardian_offline.py AUTHORITY public-key`. On the phone tap **Pin independent
   verifier**. Enter its SPKI and fingerprint; compare the fingerprint through a
   separate authenticated channel. The HTTPS pairing operation never installs or
   changes this authority pin. Wrong authority pin recovery remains blocked.
3. Run `guardian-challenge AUTHORITY/challenges`. On the phone **Generate attestation
   candidate**, paste its challenge, **Save attestation JSON**, and transfer that
   public evidence privately to the operator. Do not regenerate an existing
   enrolled candidate. Use the existing attested candidate for an installed upgrade.
4. Complete real independent enrollment (within the challenge's five-minute window):

   ```sh
   python3 scripts/guardian_offline.py AUTHORITY enroll \
     --attestation phone-attestation.json --challenge CHALLENGE_HEX \
     --binaries VERIFIER_BINARY_DIRECTORY > enrollment.fg
   ```

   Use the verified candidate SHA-256 in the authority's device ledger as `DEVICE`.
   Do not substitute a claimed fingerprint from the phone. For a still-valid
   existing offline enrollment, reuse that device record and skip generating a
   candidate or importing another enrollment. Grants last at most 24 hours; this
   prototype has no automatic renewal. Expired enrollment requires independent
   replacement with a fresh candidate after revocation, as in the offline guide.
5. Configure an operator-owned HTTPS origin with a certificate chain trusted by
   Android's system trust store and a matching hostname. Supply certificate PEM and
   private key files yourself. Keep the TLS key private. No self-signed trust
   bypass, hostname bypass, cleartext listener or automatic certificate install
   exists in the Android app. A local test certificate does not enroll a phone.
6. Issue a random, device-scoped transport token:

   ```sh
   python3 scripts/guardian_online.py AUTHORITY pair --device DEVICE
   ```

   This command requires a previously verified, active enrollment. It prints a
   fresh 256-bit token once and persists only its SHA-256 digest. Transfer it to
   the phone through an authenticated private channel. Do not put it in URLs,
   issue trackers or shell command arguments. Reissuing rotates the old token.
   There is no default password or remotely accessible token-creation endpoint.
7. Start the TLS server. It binds loopback unless explicitly configured:

   ```sh
   python3 scripts/guardian_online.py AUTHORITY serve \
     --bind PRIVATE_INTERFACE_ADDRESS --port 8443 \
     --cert TLS_CERTIFICATE_PEM --key TLS_PRIVATE_KEY_PEM
   ```

   Restrict ingress to intended clients on a private/VPN network. Operate it with
   the authority owner's account and a supervised process. Use an authenticated,
   separately confirmed origin reachable from the phone. TLS must remain intact
   to this server; it does not support a plaintext reverse-proxy backend.
8. On the phone tap **Pair HTTPS approval server**, enter the confirmed HTTPS
   origin (scheme, hostname, optional port; no path), and the private token.
   Confirm the address through an authenticated channel before tapping **Pair this
   server**. Pairing can explicitly replace transport settings after active delivery is
   resolved; it never replaces the authority pin or enrollment. Verify the address
   carefully. Pairing saves transport settings before trying enrollment, so a
   connection failure can be retried with **Fetch signed enrollment**. Re-pair
   explicitly to correct an address or enter a newly rotated token.
9. For a new phone enrollment, **Fetch signed enrollment** verifies the independently
   pinned signature, candidate key and installed APK signer. For an already
   imported, still-valid grant, leave that grant in place. Fetching another grant
   cannot replace it. Pairing alone gives no signing authority.

## Request, decision and confirmed status

On the operator machine issue a request with readable, exact scope:

```sh
python3 scripts/guardian_online.py AUTHORITY request --device DEVICE \
  --who 'Local simulated client' --what 'Read one test report' \
  --target 'Disposable test record 17'
```

The fields must be printable ASCII, each at most 1000 characters, without `|`.
The labels and values are covered by the existing authority signature. These
fields describe the authenticated authority's assertion, not separately verified
human identity. The command issues a fresh one-use nonce and at most 120-second
expiry. The phone shows the complete fields as separate readable paragraphs.

Keep the app visible. Review Who, What, Target and UTC expiry, then explicitly tap
**Approve** or **Deny**. The candidate signs the entire original request plus its
decision, after durably consuming its nonce locally. A tap is never automatic
execution. The app saves an outbox before sending and shows **Server confirmed
APPROVE/DENY** only after matching the HTTPS result to the saved nonce, candidate,
decision and `executed: false`. That confirmation is stored locally as the last
confirmation; normal polling may show a newer waiting status.

If delivery is uncertain, use **Check requests / delivery status** first. This
looks up a committed receipt for the saved nonce. If no acceptance is found and
the request is still valid, use **Send saved decision**. Replays cannot create a
second acceptance; after an ambiguous replay response, check status again.
A negative response or timeout does not prove that the server never committed.
If expired or permanently blocked, ask the operator to inspect the receipt ledger.
**Discard unconfirmed saved delivery** frees the outbox but cannot undo server
acceptance and cannot reuse the consumed local nonce. Only a fresh request can
be decided again. Dismissing review signs nothing; **Check requests** reopens it.
A signing/storage failure may burn a nonce without creating an outbox.

## API and durable state

Only four POST endpoints exist, all requiring `Authorization: Bearer TOKEN` and
`Content-Type: application/json` with a single Content-Length of 1–70000 bytes:

| Endpoint | Body | Result |
| --- | --- | --- |
| `/v1/enroll` | `{}` | Signed existing enrollment and device digest |
| `/v1/pending` | `{}` | Earliest unconsumed, unexpired signed request, or null |
| `/v1/decision` | `{"receipt": RECEIPT_OBJECT}` | Verified decision, nonce, device, executed=false |
| `/v1/status` | `{"nonce": "REQUEST_NONCE"}` | Same previously committed acceptance |

Duplicate JSON keys, extra schema fields, wrong devices, unknown routes, chunked
requests and oversized bodies refuse. Errors are deliberately generic. HTTP
redirects are refused by Android. The server does not log tokens or request bodies.
The transport uses the existing strict signed request and decision protocol; see
the offline guide for exact bytes. JSON metadata alone cannot authorize anything.
TLS authenticates delivery confirmations; they are not portable signed receipts
from the authority. The durable phone-signed receipt is stored in `state.json`.

The authority lock serializes offline CLI and online API mutations. Receipt,
acceptance and consumed flag share one fsynced atomic ledger replacement. An
uncertain `.new` commit blocks further operations; operator recovery must not
reset replay state. A status read never turns an unverified decision into approval.
The existing 8192-request ledger limit remains; do not delete old replay records
to regain space. Plan independent archival/recovery before deployment.

## Revocation and threat model

Revoke on the authority first using `guardian_offline.py AUTHORITY revoke --device
DEVICE`; this immediately blocks the token, pending delivery and outstanding
receipts. Import its signed revocation on the phone or use local revoke too.
Server revocation fails closed through API refusal; it does not automatically
install a phone tombstone. Local revoke alone does not notify the server. Replace
lost devices only through fresh independent attestation/enrollment. Never uninstall
or clear app data as an update or recovery procedure.

The security boundaries remain an uncompromised independent authority, correct
root/signer policy, Android hardware attestation/Keystore, accurate clocks and an
uncompromised unlocked app. TLS plus the explicitly confirmed origin protects the
bearer token and request confidentiality in transit. A stolen token can read that
device's action details and disrupt polling, but cannot sign decisions without its
candidate key. Device revocation invalidates the token. A compromised authority
can issue misleading requests; readable details and explicit taps cannot prove
that an operator's asserted Who is truthful. Rooted/compromised phones, overlays
and a person controlling an unlocked phone remain risks; obscured-tap filtering
and background cancellation reduce accidental approval, not malicious OS control.

TLS certificates use platform CA trust, not a silently installed pin. A malicious
trusted CA or compromised confirmed endpoint threatens transport confidentiality
and status reporting; independent authority signatures still protect request
contents and candidate signatures protect decisions. Endpoint trust and authority
trust must both be confirmed. The pairing token resides in private app preferences
with backup disabled; it is not a hardware-protected secret at rest. The candidate
private key remains nonexportable and hardware-backed.

Rate limiting permits 30 parsed authenticated-format attempts per token digest per
60-second window, with at most 1024 active digest buckets. Limits reset on process
restart. The server is intentionally single-process/single-request, with 10-second
TLS handshake/body timeouts. This is a prototype, not a hardened public Internet
service: connection floods, TLS CPU exhaustion, random-token bucket exhaustion,
and a stalled external certificate check can deny availability. Add reviewed edge
connection/IP limits, operational monitoring without sensitive payloads, durable
capacity planning and independent security review before public deployment. None
of those availability failures should grant approval. No execution integration,
production release signing, automated recovery or quorum activation is included.
