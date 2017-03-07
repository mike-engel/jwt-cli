# 0.2.0
> 2017-03-06

Second prerelease!

This adds some new features:
- JWTs can now be decoded
- RSA support for encoding and decoding

What's still missing:
- Cannot decode the header (upstream issues)
- Cannot encode or decode ES tokens
- Custom `typ` and `kid` header fields

# 0.1.0
> 2017-03-05

First prerelease! 0.1.0

This is the first prerelease of `jwt-cli`. The name will change
eventually.

The following features are supported:

- encode a JWT
- provide a custom algorithm, payload, and secret

What's missing:

- can't change the `typ` or add a `kid` to the header
- only supports HMAC algorithms
- it hasn't been refactored

What I'm planning:

- support for all algorithms
- refactor to be even more functional
- submit an upstream patch to frank_jwt to allow custom `typ` and `kid` headers
