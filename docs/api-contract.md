# API contract

Every managed resource has a mandatory `providerRef`. Provider, owner, and
remote name fields are immutable. Existing objects are adopted by their natural
key and declared fields are authoritative; unspecified remote fields and child
objects are preserved. Collections are pruned only with `prune: true`.

`deletionPolicy` defaults to `Orphan`. `Delete` adds a finalizer and removes the
remote object before generated Secrets. Orphaning retains generated Secrets.
Generated values are stable and rotate only when `rotationNonce` changes.

Status exposes remote ID, observed generation, generated Secret references,
last reconciliation time, and `Ready`, `Synced`, and `Degraded` conditions.
Credentials are never copied to specs, status, events, or logs.

The operator watches all namespaces, but all Secret references are resolved in
the custom resource's namespace.

## User signing keys

2026-11-11: `ForgejoGPGKey` manages an OpenPGP signing key for an existing user.
It uses the referenced provider's **site administrator API token** with
`Sudo: <user>` on Forgejo 17's `/user/emails` and `/user/gpg_keys` routes.
The token needs user/email and GPG-key permissions. 2026-11-11: the provider
must explicitly authorize exact logins in `spec.gpgKeys.allowedUsers`; unset or
empty disables this feature. A CR must share the provider's namespace unless its
namespace is explicitly listed in `spec.gpgKeys.allowedNamespaces` (no wildcards).
Site administrator targets are always refused, even when allowlisted, before
reading emails or key material. Protect provider writes as credential policy.
The output Secret always lives beside the CR. For the example below, set the
provider policy to `gpgKeys: {allowedUsers: [renovate], allowedNamespaces: [argo]}`.

```yaml
apiVersion: forgejo.jakeschurch.com/v1alpha1
kind: ForgejoGPGKey
metadata:
  name: renovate
  namespace: argo
spec:
  providerRef: code-jakeschurch
  providerNamespace: forgejo
  user: renovate
  identity:
    name: Renovate
    email: renovate@localhost.invalid
  algorithm: ed25519
  deletionPolicy: Orphan
  secretRef:
    name: renovate-signing-key
    keys:
      privateKey: privateKey
      publicKey: publicKey
      keyID: keyID
      fingerprint: fingerprint
  rotation:
    after: 2160h
    gracePeriod: 336h
```

The identity email must be an activated address on that account. The operator
checks it before generation or registration and reports `EmailVerified=False`
on failure. It never activates or edits account emails. Provider, user, identity,
algorithm and Secret coordinates are immutable. The default `ed25519` produces
a v4 EdDSA signing key and cv25519 encryption subkey; `rsa4096` is also supported.

An absent Secret is generated in-process using ProtonMail/go-crypto, and the
public key is registered before the consumer Secret is created (also after
Secret loss). The four output keys default as shown; the exports are ASCII
armored. Existing Secrets must already be controlled by this CR; unowned or
foreign Secrets are refused rather than adopted.
Only the public key is sent to Forgejo. Missing remote keys are re-registered
without changing private material. Deleting a key in the Forgejo UI is therefore
not revocation: delete its Kubernetes Secret to generate a replacement, or delete
the CR with `deletionPolicy: Delete` to remove all its managed public keys. Status adds `keyID`, `fingerprint`,
`KeyRegistered`, `EmailVerified` and a public key-ID cleanup journal.

Omit `rotation.after` to disable automatic rotation. Both durations must be
positive; the grace defaults to 24h. A pending private key is persisted under the
reserved `forgejoPendingPrivateKey` data key before registration; promotion
atomically replaces the four outputs and stores a retirement deadline in the
`forgejo.jakeschurch.com/gpg-state` annotation. Restarts replay this transaction.
Rotation waits for previous retirement before producing another candidate.
Consumers should reference only `privateKey`, rather than mount the entire
Secret or use `envFrom`, which also exposes the staged private key.
Secret/provider events wake reconciliation; remote drift and time deadlines
are checked at most every ten minutes (one-minute retry on errors).

Consumers using environment variables need a new pod to read the rotated key.
Set grace longer than any outstanding signing run or queued head: removing an
old public key also ends Forgejo verification of its historical signatures.
Secret loss generates a replacement and retires keys from the durable journal.
If status is lost during grace, the journal is rebuilt from the owned Secret's
retirement annotation intersected with keys still present on the target account.
`deletionPolicy` defaults to `Orphan`: no finalizer, remote public keys retained,
and Kubernetes garbage collects the owned Secret. `Delete` removes only this
CR's journaled keys and holds its finalizer on API failures. Switch to `Orphan`
to release deletion without a provider. `prune` and `rotationNonce` do not apply.

API references: [Forgejo 17 Sudo routing](https://codeberg.org/forgejo/forgejo/src/tag/v17.0.1/routers/api/v1/api.go),
[user GPG operations](https://codeberg.org/forgejo/forgejo/src/tag/v17.0.1/routers/api/v1/user/gpg_key.go),
and [activated email listing](https://codeberg.org/forgejo/forgejo/src/tag/v17.0.1/routers/api/v1/user/email.go).

## Repository merge detection

`ForgejoRepository.spec.allowManualMerge` permits Forgejo's native API to record
an already-landed Git merge. `autodetectManualMerge` enables Forgejo's own detection
when a push includes a pull request's commits. Git-based merge queues should set
both to `true`; no queue-specific merge detection is implemented by the operator.

These optional booleans preserve remote settings when omitted. Explicit `false`
disables the corresponding setting. Settings are reconciled on initial creation
as well as adoption, and normal repository drift reconciliation restores them.

## Access tokens for human users

`ForgejoAccessToken` mints for a managed robot by default. Minting for an
existing person needs both halves below; a `username` typo on a robot CR only
ever produces the robot error.

- The CR sets `accountType: Human` (immutable).
- The CR's provider sets `humanAccessTokens`, listing the exact username in
  `allowedUsernames` and naming a Secret with `username` and `password` keys for
  a site administrator in `adminCredentialsSecretRef`.

The CR must be in the provider's namespace, so `providerNamespace` cannot extend
this to other namespaces. The allowlist is only a boundary if those who can create
these CRs cannot edit the provider; grant the two separately. Scopes are not
limited beyond requiring at least one.

Forgejo requires password authentication on `POST /users/{username}/tokens` and
`DELETE /users/{username}/tokens/{id}`. An admin API token is rejected even with
`Sudo`, so the provider token cannot be used. The operator reads the administrator
password and never changes any account: it only creates and deletes tokens.
Forgejo also refuses that administrator's password while the account has TOTP
enrolled (401, on every request), and the operator cannot supply a one-time code,
so `adminCredentialsSecretRef` must name an administrator without TOTP. TOTP on the
person being minted for does not matter.

A rotation (`rotationNonce` change) or `deletionPolicy: Delete` removes only the
token id this CR recorded in `status.remoteID`, never a token matched by name. If
the name is already used on the account, creation fails and the CR reports it until
that token is removed in Forgejo. Removing a username from the allowlist degrades
the CR but neither revokes the token nor deletes its Secret. An existing Secret
without the operator's rotation annotation is refused rather than overwritten.

## Access tokens for robots

The same endpoints authenticate as the robot, with the password Secret of the
`ForgejoRobotAccount` whose `username` matches; the provider token is refused here
too. A rotation or `deletionPolicy: Delete` revokes the robot's token named
`spec.name`, since the operator owns that account. The name is resolved to an id by
listing the account's tokens, because Forgejo reads a numeric path segment as an id.

`deletionPolicy: Delete` needs that password to be available. If the account no
longer exists its tokens are gone and deletion succeeds. Otherwise, without a usable
password (the robot CR or its Secret was removed, and the account was orphaned), the
CR stays `Degraded` and retries; set `deletionPolicy: Orphan` to keep the token and
let it go.
