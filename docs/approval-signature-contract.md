# USC signed approval contract — Stage 1 design

**Status:** design proposal for the synthetic-only runner prototype  
**Execution status:** no signature verifier or signer is implemented by this document  
**Customer repositories:** remain disabled

## 1. Security objective and boundary

The runner broker must not accept a job merely because a caller supplies an arbitrary approval ID. It must verify a cryptographic signature made by a configured approval authority over the exact job policy and source identity.

The approval authority's private key must remain outside the runner broker and outside the build VM. The broker receives only a trusted public key. The control-plane UID may forward a signed approval but must not be able to create a valid one.

A valid signature proves that the configured key signed the canonical approval payload. **It does not, by itself, prove a human personally approved the job.** Human identity, authentication, review UI, and consent capture belong to the approval authority and are not implemented here. CI signatures are synthetic fixtures only.

## 2. Algorithm and verifier

- Signature algorithm: Ed25519.
- Verification utility: OpenSSL `pkeyutl`, invoked through a fixed absolute executable path (`/usr/bin/openssl`).
- Use `pkeyutl -verify -pubin -inkey <trusted-public-key> -sigfile <temporary-signature> -rawin`; the canonical payload is supplied on standard input.
- No shell, caller-supplied executable, caller-supplied file path, or generic command interface is permitted.
- The verifier uses a short timeout, bounded payload/signature sizes, fixed environment, closed inherited file descriptors, and suppressed subprocess output.
- Temporary signature bytes are written to a 0600 file in the runner-private 0700 state directory and removed after verification.
- Missing OpenSSL, unsupported key format, timeout, invalid signature, or any verifier error fails closed. There is no unsigned fallback.

OpenSSL's `pkeyutl` documentation describes Ed25519/Ed448 raw-message signing and verification and the `-rawin` option: https://docs.openssl.org/3.3/man1/openssl-pkeyutl/

This introduces OpenSSL as a trusted host utility. The host image/provisioning process must install and maintain it. The broker does not invoke it for any purpose other than signature verification.

## 3. Trusted public-key handling

- The broker is configured with one public-key PEM file and computes `key_id = lowercase_hex(SHA256(exact_PEM_file_bytes))`.
- The public-key path is trusted service configuration, never request data.
- The file must be an absolute, non-symlink, single-link regular file, no larger than 4 KiB, readable by the broker, and not writable by group or other users.
- The private key is held by a separate approval-authority identity in a 0700 directory and a 0600 file. It is never copied into the broker state directory, control-plane account, build VM, or build container.
- The control-plane and runner UIDs must fail filesystem read checks against the private-key path in the ephemeral CI fixture.
- Initial implementation trusts one configured key. Key rotation requires a reviewed configuration change; no remote key discovery or automatic trust expansion is allowed.

## 4. Protocol version 2 submit contract

The submit envelope retains a unique transport `request_id`, but the signed approval is a separate object inside `job`:

```json
{
  "protocol_version": "2",
  "request_id": "transport-request-uuid",
  "operation": "submit",
  "job": {
    "source_snapshot_sha256": "64 lowercase hex characters",
    "profile_id": "python-pytest",
    "build_image_digest": "image@sha256:64-lowercase-hex",
    "exporter_image_digest": "image@sha256:64-lowercase-hex",
    "policy_version": "usc-runner-policy-v1",
    "release_authorized": false,
    "approval": {
      "approval_id": "approval-uuid",
      "issued_at": "UTC ISO-8601 timestamp",
      "expires_at": "UTC ISO-8601 timestamp",
      "nonce": "random-uuid",
      "requester_uid": 12345,
      "key_id": "64 lowercase hex characters",
      "signature": "base64-encoded 64-byte Ed25519 signature"
    }
  }
}
```

The exact schema rejects unknown/missing fields, duplicate JSON keys, noncanonical UUIDs, invalid digest pins, unsupported profiles/policies, non-boolean release flags, malformed timestamps, and malformed base64.

## 5. Canonical signed payload

The signature covers a deterministic JSON object containing exactly:

- protocol version
- approval ID
- issued-at timestamp
- expiry timestamp
- nonce
- requester UID
- key ID
- source snapshot SHA-256
- profile ID
- build image digest
- exporter image digest
- policy version
- `release_authorized: false`

Canonical serialization is UTF-8 JSON with sorted keys, separators `(",", ":")`, and `ensure_ascii=True`. No floats or non-standard JSON constants are allowed. The signature field itself and transport `request_id` are not included.

The broker independently rebuilds these canonical bytes from validated fields. It never trusts a caller-supplied canonical payload.

## 6. Time, identity, and replay rules

- `requester_uid` must be a positive non-root UID and exactly equal the kernel `SO_PEERCRED` UID for the submitting connection.
- The peer UID must also be in the configured submitter/operator allowlist.
- `issued_at` may be at most 60 seconds in the future.
- `expires_at` must be in the future, later than `issued_at`, and no more than 30 minutes after issue time.
- The key ID must match the configured public-key fingerprint.
- Signature bytes must decode strictly and be exactly 64 bytes.
- `request_id`, `approval_id`, and `nonce` are independently unique in broker-owned durable state.
- Signature verification and all three replay-record writes occur before acceptance, in one SQLite transaction. A failed transaction leaves no accepted job or consumed replay record.
- The signed approval cannot authorize release: `release_authorized` is fixed to false and included in the signed payload.

## 7. Trust assumptions and failure behavior

Trusted components include the host kernel, root/admin provisioning, the OpenSSL binary and its host package chain, the approval authority identity and private-key custody, the configured public-key file, the broker executable, and the broker-owned state directory/database.

Fail closed on: missing public key, unsafe key-file permissions, unknown key ID, invalid signature, invalid requester UID, expiry/clock failure, nonce/approval/request replay, missing OpenSSL, verifier timeout, SQLite failure, or cleanup failure.

The design does not defend against host root, kernel compromise, compromise of the approval authority/private key, or a malicious trusted signer.

## 8. Implementation gates

1. Implement protocol v2 exact-schema validation and canonical payload generation, with no broker execution changes.
2. Implement the fixed OpenSSL Ed25519 verifier and trusted public-key file checks.
3. Extend durable state schema to store unique nonces and approval metadata; reject old schema versions rather than silently migrating untrusted state.
4. Add an ephemeral third approval-authority UID in CI. Generate a synthetic Ed25519 key there, prove the broker/control-plane cannot read the private key, and submit only the signed fixture.
5. Test field-by-field tampering, wrong key, invalid signature, malformed signature encoding, requester mismatch, expiry, replay across restart, missing verifier, and transaction rollback.
6. Update the example service configuration to pass only the public-key path. Never include private-key material in service configuration.
7. Obtain independent security review before considering customer-source execution.

No customer repositories, real customer source, Docker build execution, artifact release, or production deployment are authorized by this design.
