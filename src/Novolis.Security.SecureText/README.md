<!-- novolis-pkg-brand:start -->
<p align="center">
  <a href="https://github.com/Novolis-Platform/novolis-security">
    <img src="https://raw.githubusercontent.com/Novolis-Platform/.github/main/brand/logo-icon.svg" width="72" alt="Novolis"/>
  </a>
</p>
<!-- novolis-pkg-brand:end -->

# Novolis.Security.SecureText

Cryptographic device identities and primitives for the Novolis secure-text v1 protocol.

## Guarantees

- P-256 ECDSA-signed public device bundles.
- P-256 ECDH pairwise key agreement.
- HKDF-SHA-256-derived AES-256-GCM conversation keys.
- A fingerprint that users explicitly compare and pin before accepting a peer.
- Authenticated ciphertext only; plaintext belongs at the endpoints.

## Security model

The relay may observe, retain, replay, delay, drop, or alter envelopes. It must not learn
message content or successfully alter a valid message. JWTs and transport TLS control relay
access; they do not establish peer cryptographic trust.

Before communication, users compare the full bundle fingerprint through an independent trusted
channel and create a `SecureTextTrustedPeer`. A changed fingerprint blocks delivery until the
users repeat this confirmation.

Secure-text v1 uses static, authenticated pairwise ECDH. It does **not** claim a ratchet,
post-compromise security, group messaging, multi-device synchronization, or forward secrecy.
Applications requiring those properties must use an audited ratchet protocol rather than extend
this package.

## Private-key storage

Private keys are exported only so a host can place them in platform-protected storage through
`ISecureTextKeyStore`. Do not write them to configuration, logs, backups, source control, or an
ordinary file. Device loss or intentional revocation requires generating a new identity, publishing
a new public bundle, and repeating the fingerprint confirmation.

## Quick start

```csharp
using Novolis.Security.SecureText;

var localIdentity = SecureTextDeviceIdentity.Create();
var localBundle = SecureTextPublicBundle.Create(localIdentity);

// Obtain this through the relay, then compare its fingerprint with the peer out of band.
SecureTextPublicBundle peerBundle = GetPeerBundle();
var trustedPeer = new SecureTextTrustedPeer(peerBundle);
trustedPeer.VerifyBundle(peerBundle);
```

The transport-neutral envelope and replay policy live in
`Novolis.Messaging.SecureText`.
