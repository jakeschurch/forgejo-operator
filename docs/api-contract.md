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

A rotation (`rotationNonce` change) or `deletionPolicy: Delete` removes only the
token id this CR recorded in `status.remoteID`, never a token matched by name. If
the name is already used on the account, creation fails and the CR reports it until
that token is removed in Forgejo. Removing a username from the allowlist degrades
the CR but neither revokes the token nor deletes its Secret. An existing Secret
without the operator's rotation annotation is refused rather than overwritten.
