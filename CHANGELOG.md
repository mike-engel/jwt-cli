# Unreleased

# 6.0.0

> 2023-06-22

#### BREAKING

- [BREAKING] Update from clap 3 to clap 4.
  This forces the use of `--exp`/`-e` to require an `=` sign, which was not required before. This means that when you used to be able to write `--exp +365d`, you must now write `--exp=+365d`. This is only required for this flag.

#### New features

- Added `--out` argument to save output to a file #221
- Added support for EdDSA #238
- Added `--date` argument to change the display format of the timestamps #235
- Added `--no-typ` argument to prevent `typ` from being added to the header
- Add Scoop installation info #241
- Add Macports installation info #231

#### Changes

- Dependency updates
- Remove Gofish installation info. See #228
- Update from jsonwebtoken 7 to 8

#### Fixes

- Added better error handling for improper secret and algorithm combinations

# 5.0.3

> 2022-04-27

#### Changes

- Added instructions for installing on Arch linux #181
- Added repository information for crates.io #184
- Updates dependencies

# 5.0.2

> 2022-01-20

### Fixes

- Fixes parsing of systemd.time date strings when they're in the past

### Changes

- Updates dependencies

# 5.0.1

> 2022-01-12

### Changes

- Upgrade clap to version 3 #164

# 5.0.0

> 2021-11-14

#### New features

- Secrets can be files for both encoding and decoding #130
- Support `RSASSA-PSS` signatures #132
- **[BREAKING]** `jwt-cli` will always validate `exp` unless you pass `--ignore-exp` #137
- Swapped out [term-painter](https://github.com/LukasKalbertodt/term-painter#when-not-to-use-this-crate) for [bunt](https://crates.io/crates/bunt)
- Allow the secret to be base64 encoded #144
- Show help if no subcommands are used #146

# 4.0.0

> 2021-02-16

#### New features

- **[BREAKING]** Remove the `prn` option as it's not included in the spec any longer #114
- **[BREAKING]** Avoid adding an `exp` claim automatically. Instead, the `--exp` flag must be present, with or without a value
- Support adding `jti` when encoding
- Add `no-iat` flag to disable automatic `iat` claim generation
- Add an `--iso8601` flag to represent date-based claims as ISO 8601 date strings. Only applies to `iat`, `exp`, and `nbf`

#### Bug fixes

- Trim whitespace around a jwt before encoding #120

# 3.3.0

> 2020-12-24

#### New features

- Default decoding to JSON when not in a TTY #100

# 3.2.1

> 2020-09-13

#### Bug fixes

- Fix binary archives uploaded during release

# 3.2.0

> 2020-09-11

#### New features

- When piping the output of `jwt` to another command, `jwt` won't add a trailing newline

#### Bug fixes

- When verifying token without an `exp` claim, `jwt` won't print that the jwt is invalid

# 3.1.0

> 2020-04-17

#### New features

- Durations (`exp`, and `nbf`) can now be set with relative times #68

# 3.0.1

> 2020-03-14

#### Bug fixes

- Re-release for cargo installers

# 3.0.0

> 2020-03-14

#### New features

- Updated [`jsonweboken`](https://github.com/keats/jsonwebtoken) to version 7, which now allows PEM secrets to be used
  - This requires the filename to end with `.pem` to be detected correctly

# 2.5.2

> 2020-02-02

#### Bug fixes

- Prevent an invalid JWT token from causing a panic during `decode` #51

# 2.5.1

> 2019-10-07

#### Bug fixes

- 2.5.1 fixes a nasty bug where non-string JSON values would be dropped during encoding

# 2.5.0

> 2019-05-29

#### New features

- Add support for ECDSA algorithms. For now, only ES256 and ES384 are supported. [#12](https://github.com/mike-engel/jwt-cli/issues/10)

# 2.4.0

> 2019-04-19

#### New features

- Add support for stdin on `encode` and `decode`. Instead of passing a JSON body or a JWT token, you can simply pass `-`. [#10](https://github.com/mike-engel/jwt-cli/issues/10)

#### Minor changes

- Updated the project to use rust 2018 edition
- Update dependencies

# 2.3.0

> 2019-01-10

#### New features

- Adds the ability to include a private/public key from a file on the local filesystem using the `@` shorthand [#9](https://github.com/mike-engel/jwt-cli/pull/9)

# 2.2.1

> 2018-11-28

#### Bug fixes

- Add a missing `>` to Aaron's entry in the contributors section of `Cargo.toml`

# 2.2.0

> 2018-11-18

#### Minor changes

- You can now use a fully qualified and valid JSON string as the entire payload body. Add it to the end of the command without a flag to use it. It can be combined with the `-P` and `--payload` flags to enhance a JSON string.

# 2.1.0

> 2018-09-24

#### Minor changes

- A new output format has been added: JSON! Use the `--json` or `-j` flags to output a pure JSON representation of the header and payload, which can be piped into other programs like `jq` [[#6](https://github.com/mike-engel/jwt-cli/pull/6)]

# 2.0.0

> 2018-04-28

#### Breaking (maybe) changes

- Updated to `jsonwebtoken` version 4
- JWTs without the `typ` header can now be decoded

# 1.2.0

> 2017-09-05

Better stdout and stderr interop

#### Minor changes

- Errors are now printed to STDERR instead of STDOUT
- Proper exit codes should now be emitted. `0` for successes, `1` for failures.
- The output from the encode command is now just the token, which can be piped or stored in a shell

# 1.1.0

> 2017-07-13

The decoding and validation release!

#### New features

- If the JWT you're decoding is invalid, it will still print out the head and claims objects
- Error messages are now red and bold for better visibility
- Secret is no longer required for decoding a JWT, but will be validated if one is provided
- Added info on how to install the binary through homebrew

#### Bug fixes

- The proper version number is now displayed in the help commands (and `Cargo.toml` file)

# 1.0.0

> 2017-07-03

The 1.0 release!

This is the initial non-beta, non-alpha release of jwt-cli!

#### New features

- Everything is parsed by serde now. You can pass strings, numbers, arrays, objects, whatever. If serde can parse it, it's valid!

#### Things left to do

- Add jwt-cli to package managers!

# 0.9.1

> 2017-07-03

The forkless release!

#### Bug fixes

- Swaps out my fork of `jsonwebtoken` for the master branch of keats' `jsonwebtoken`

#### Roadmap to 1.0

- Allow for json payload items via `-P this=json(['arbitrary', 'data'])`

# 0.9.0

> 2017-07-03

The `iat` and `exp` release!

#### Breaking changes

- `iat` is now automatically added to the claims object
- `exp` is now automatically added to the claims object if not passed in directly
- `exp` defaults to 30 minutes from the time of creation

#### Bug fixes

- `exp` and `nbf` are now parsed as numbers, not string

#### Temporary changes

- Moves to my instance of `jsonwebtoken` until some PRs are merged

#### Roadmap to 1.0

- Allow for json payload items via `-P this=json(['arbitrary', 'data'])`

# 0.8.1

> 2017-07-02

#### Bug fixes

- Fix tests so that they pass

# 0.8.0

> 2017-07-02

Dependency updates

#### Breaking changes

- Swaps out `rustc_serialize` for `serde`
- Updates `jsonwebtoken` from version 1 to version 2. This allows for much more precise errors, and expands potential for validation.

#### Roadmap to 1.0

- Automatically set `iat` and `exp`
- Default `exp` to 30 minutes from now
- Allow for json payload items via `-P this=json(['arbitrary', 'data'])`

# 0.7.0

> 2017-03-13

The whoopsies release!

While actually using the project, I found that payload claims were being nested into a root key. Whoops!

#### Breaking changes

- The `generate` command is now `encode`

#### New features

- When decoding, the `algorithm` option is no longer required (defaults to HS256)
- Updated to rust 1.16

#### Bug fixes

- Payload claims are no longer nested in a `_field0` key

#### Roadmap to 1.0.0

- Automatically set `iat` and `exp`
- Default `exp` to 30 minutes from now
- Swap out rustc_serialize for serde
- These are all blocked by keats/rust-jwt#19 :(
- Testing on Windows and Linux

# 0.6.0

> 2017-03-12

The rename release!

#### Breaking changes

- Renamed the release binary to `jwt`. During development, either `jwt` or `jwt-cli` is available.

#### Roadmap to 1.0.0

- Testing on linux & windows (this was developed on macOS)
- Work on releasing 1.0.0 to homebrew and chocolatey.

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

This is the first prerelease of `jwt`. The name will change
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
