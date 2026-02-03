# Bailey

[![Clojars Project](https://img.shields.io/clojars/v/com.sturdystats/bailey.svg)](https://clojars.org/com.sturdystats/bailey)

**Bailey** is a small, opinionated Clojure library for managing **server-side encryption keys** with strong operational safety.

Bailey was originally developed to meet the internal security and operational requirements of **Sturdy Statistics**. 
It is published as open source to support transparency, auditability, and reuse, but its design is intentionally conservative and driven by real production needs.
We may not accept feature requests that dilute its focus.

It is designed for applications that need:
- deterministic, auditable encryption
- safe key rotation
- offline “break-glass” recovery
- compatibility with modern operational security practices (TPM-sealed secrets, immutable artifacts, atomic writes)

Bailey does **not** implement cryptographic primitives.
It uses the well-reviewed library [Tempel](https://cljdoc.org/d/com.taoensso/tempel) to implement  a robust, auditable key lifecycle.

## Installation

Add to `deps.edn`:

```clojure
{:deps {com.sturdystats/bailey {:mvn/version "VERSION"}}}
```

## Design goals

Bailey is built around a few explicit goals:

- **Separation of mechanism and policy**
  Bailey provides *how* keys are managed, not *who* owns them or *where* secrets come from.

- **Recoverability without fragility**
  Encrypted data must remain recoverable even if:
  - the server is lost
  - the encrypted keychain file is corrupted or deleted
  - routine credentials are rotated or invalidated

- **Operational clarity**
  All key material has a clear lifecycle:
  - generation
  - storage
  - rotation
  - recovery

- **Auditability**
  The logic for key handling is small, explicit, and readable. This library is intended to simplify security reviews, not complicate them.

## What Bailey does

Bailey manages **three distinct layers of keys**:

### 1. Offline backup key (long-term, asymmetric)

- Generated once, offline
- Private key stored securely (e.g. password manager, HSM, vault)
- Public key embedded in the application at build time
- Used **only** for recovery and “belt-and-suspenders” encryption

This key allows recovery even if the server’s encrypted keychain is lost or corrupted.

### 2. Server keychain (encrypted at rest)

- Stored on disk, encrypted
- Unlocked at runtime using a password supplied by the host (e.g. TPM-sealed secret)
- Contains one or more **symmetric encryption keys**
- Automatically created if missing

This keychain is recoverable using the offline backup key.

### 3. Symmetric data encryption keys (rotatable)

- Used for routine encryption/decryption
- Rotatable without breaking access to old data
- Old keys are retained to allow decryption of historical ciphertexts

## What Bailey does *not* do

- No custom cryptography
- No network services
- No key escrow
- No opinionated secret storage backend
- No automatic password prompting at runtime

Bailey assumes **you** control:
- how passwords are sourced
- how offline keys are stored
- how artifacts are deployed and verified

## Threat model

Bailey is designed with the following assumptions:

### Adversary capabilities (assumed possible)

- Reads application source code and dependencies
- Obtains encrypted keychain files from disk
- Obtains encrypted application data
- Observes runtime behavior indirectly (logs, crashes)

### Adversary capabilities (assumed *not* possible)

- Compromises the TPM or equivalent secure enclave
- Accesses offline backup key material
- Modifies deployed artifacts without detection
- Executes arbitrary code inside the running process

### Security goals

- Encrypted data remains confidential without access to active server keys
- Loss of the encrypted keychain file does **not** cause permanent data loss
- Routine key rotation does not invalidate historical data
- Backup recovery requires deliberate, offline action

## Typical usage

### 1. Generate offline backup keys (admin / build-time)

Run **once**, offline or in CI:

```clojure
(bailey.core/generate-backup-keys!
 {:secrets-dir   "secrets"      ;; secure, offline storage
  :resources-dir "resources"})  ;; public key embedded in app
```

- The full encrypted keychain **must be stored securely and offline**
- The public key may be committed to version control

### 2. Initialize keys at server startup

```clojure
(bailey.core/init!
 {:secrets-dir "var/bailey"
  :read-server-password!!
  (fn []
    ;; must return a fresh byte[] each call; result zero'd in place after use
    (read-tpm-sealed-secret))})
```

This will:
- load the embedded backup public key
- load or create the encrypted server keychain
- unlock it using the supplied password

### 3. Encrypt and decrypt data

```clojure
(def ciphertext
  (bailey.core/encrypt (.getBytes "secret data")))

(def plaintext
  (bailey.core/decrypt ciphertext))
```

For especially critical data:

```clojure
(bailey.core/encrypt-critical (.getBytes "critical config"))
```

This adds asymmetric backup encryption so the data is recoverable even if the server keychain is lost.

### 4. Rotate server keys

```clojure
(bailey.core/rotate-keys!
 {:read-server-password!! read-tpm-sealed-secret})
```

- A new symmetric key becomes primary
- Old keys are retained for decryption
- The encrypted keychain file is atomically updated

## Recovery

Bailey provides **explicit recovery tools** intended for offline, administrative use.

Given:
- the encrypted server keychain file
- the encrypted offline backup keychain
- the backup password

You can recover the server keychain and decrypt protected data without access to the original server.

This is a deliberate, manual process by design.

## Operational recommendations

- Use artifact signing and verification for deployed jars
- Protect keychain directories with strict filesystem permissions
- Disable core dumps for production services
- Run the application with least privilege
- Keep offline backup keys truly offline

## License

Apache License 2.0

Copyright © Sturdy Statistics

<!-- Local Variables: -->
<!-- fill-column: 1000000 -->
<!-- End: -->
