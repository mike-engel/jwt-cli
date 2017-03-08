# 0.3.1
> 2017-03-07

This fixes the CI scripts, so now it should build and publish them correctly,
I hope.

# 0.3.0
> 2017-03-07

Third prerelease.

Overall, this replaces frank_jwt with jsonwebtoken. What does that mean?

- You can now specify the `kid` header
- You can now decode and display the header
- RSA signatures are no longer supported

There were also some other enhancements:

- If a decoded token is invalid, you can now get better context for the error

And here's a list of stuff that's still wacky:

- The decoded token output can be so much better
- RSA and ECDSA signing would be super neat
- JWS and JWE type tokens would be good to have as well

Finally, there should be builds available for linux, macOS, and windows
thanks to some CI magic.

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
