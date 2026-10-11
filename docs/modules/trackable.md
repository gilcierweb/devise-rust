# `trackable`

Mirrors `Devise::Models::Trackable`
(`devise/lib/devise/models/trackable.rb` and
`devise/lib/devise/hooks/trackable.rb`, untracked upstream reference).
Sign-in auditing: the counter and timestamp fields shift current into
last on every sign-in, stamp the current values, and bump
`sign_in_count`, with the issue #4673 new-record guard on the persisting
variant.

The trait lives at
[`devise_rust::trackable::Trackable`](https://docs.rs/devise-rust/latest/devise_rust/trackable/trait.Trackable.html).

## Options

Trackable adds no options, matching Devise.

## Examples

`update_tracked_fields` shifts the fields on the record (first sign-in
sets last equal to current); `update_tracked_fields_bang` persists
validation-free through the forced-write verb after probing the adapter
for the record key, and returns without writing when the record is
absent:

<!-- text fence: adapter and clock parameters; compiled in the trackable
     model tests and the example apps -->
```text
user.update_tracked_fields(clock.now(), "127.0.0.1");
assert_eq!(user.sign_in_count(), 1);

user.update_tracked_fields_bang(Some("127.0.0.1"), &adapter, &clock).await?;
```

The IP input is the socket peer address carried on
`AuthRequest::peer_addr`. `X-Forwarded-For` and every other proxy header
are never read here: only the framework-supplied socket address enters
the sign-in record.

## Chaining note

`trackable` is tenth and last in the Devise module super-chain (lib.rs
chain position 9). It adds no `active_for_authentication` or
`inactive_message` condition: its hook runs after sign-in (the warden
`after_set_user except: :fetch` equivalent) and is skipped by the
`skip_trackable` request flag, mirroring Devise's hook semantics.
