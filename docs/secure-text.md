# Secure-text v1 protocol

## Scope

Secure-text v1 protects one text conversation between two known devices. It separates
cryptographic message protection from delivery: SignalR, Local IPC, TCP, HTTP/WebSocket, and
Service Bus can carry the same opaque envelope.

## Threat model

The delivery service, storage layer, and network can read, retain, replay, delay, drop, and alter
messages. They must not recover plaintext or create a valid altered envelope. The protocol does
not conceal routing metadata: conversation id, sender device id, recipient device id, message
time, size, and ordering counter remain visible to a relay.

TLS/WSS remains mandatory for non-local deployments. It protects credentials and metadata in
transit but does not replace message-level end-to-end encryption.

## Device enrollment and trust

1. A device creates independent P-256 ECDSA and ECDH private keys.
2. It signs a public bundle containing its device id, public keys, and validity window.
3. The relay registers only that public bundle.
4. A peer obtains the bundle and verifies its self-signature.
5. Users compare the displayed SHA-256 bundle fingerprint through an independent trusted channel.
6. The peer pins the verified fingerprint in `SecureTextTrustedPeer`.

The self-signature detects accidental or relay-side changes after pinning. It cannot make an
unverified key trustworthy: fingerprint confirmation is required before a bundle is accepted.

## Message protection

For a pinned pair, P-256 ECDH derives a shared secret. HKDF-SHA-256 derives a 32-byte AES-GCM
key from the shared secret, conversation id, sorted pair of bundle fingerprints, and key epoch.
Each message has a fresh 96-bit random nonce. AES-256-GCM authenticates the ciphertext and the
canonical header containing protocol version, message id, conversation id, sender and recipient
device ids, epoch, counter, and sent time.

The counter is monotonic per sender and epoch. Recipients retain a bounded replay window and
reject duplicate, stale, or implausibly far-ahead counters only after successful authentication.

## Key lifecycle

- Bundles expire after the configured validity window.
- A key change, expiry, suspected compromise, or device replacement creates a new device identity
  and public bundle.
- Peers reject a changed fingerprint until the users complete confirmation again.
- An application may start a new epoch only after both peers have the corresponding verified
  bundle. Epoch changes are not automatic negotiation.
- Private-key loss makes prior protected text unavailable. Recovery is a new enrollment, not key
  escrow.

## Limits

V1 is not a Signal-compatible ratchet protocol. It makes no forward-secrecy or post-compromise
security claim, does not define offline prekeys, group sender keys, device synchronization,
read-receipts, deletion semantics, or metadata privacy. Do not add those properties by evolving
the static scheme; choose an independently audited protocol implementation instead.
