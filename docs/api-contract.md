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
