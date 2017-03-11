# 0.5.0
> 2017-03-10

The testing release!

This adds a bunch of unit tests for almost all of the functions (`println!`
functions excluded) and fixes some tests found after writing them.

#### Breaking changes
- The short forms for `payload` and `principal` have how been switched for
consistency
- The long form of `expires` is now `exp` for consistency

#### Bug fixes
- Shorthand payload options (`exp`, `aud`, etc) no longer cause a panic
- Windows builds now have a more readable name rather that the target triple
- The generate command output is now prettier

#### Roadmap to 1.0.0
- Final preflight checks
- Investigation into release to OS package managers
- Name change?

# 0.4.1
> 2017-03-10

This adds documentation in the readme, as well as some github templates.

Additionally, the travis build config should be be fixed, and builds for macOS
and linux should now be uploaded to the release.

Roadmap to 1.0.0:

- Unit tests
- Possible upstream patches to get more functionality

# 0.4.0
> 2017-03-09

This one's all about the formatting from decode! When you decode a JWT now, it
looks spectacular, if I do say so myself. It's even colored and bold and other
great stuff.

This also fixes the build script, so now macOS, Windows, and Linux binaries
should all be present in the release.

Roadmap to 1.0.0:

- Unit tests
- Possible upstream patches to get more functionality

# 0.3.2
> 2017-03-08

This removes the builds for Windows GBU, \*BSD, armv7, and aarch64. Sorry if you
use those systems or architectures.

This also fixes some of the builds where it would find unreachable code. It's
ok, I promise.

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
