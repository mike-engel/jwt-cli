# jwt-cli

A super fast CLI tool to decode and encode JWTs built in [Rust](https://rust-lang.org).

[![Build Status](https://travis-ci.org/mike-engel/jwt-cli.svg?branch=master)](https://travis-ci.org/mike-engel/jwt-cli)
[![Build status](https://ci.appveyor.com/api/projects/status/9p1lqbo8cmhixdns/branch/master?svg=true)](https://ci.appveyor.com/project/mike-engel/jwt-cli/branch/master)
[![GitHub release](https://img.shields.io/github/tag/mike-engel/jwt-cli.svg)]()

`jwt-cli` is a command line tool to help you work with JSON Web Tokens (JWTs). Like most JWT command line tools out there, you can decode almost any JWT header and claims body. Unlike any that I've found, however, `jwt-cli` allows you to encode a new JWT with nearly any piece of data you can think of. Custom header values (some), custom claim bodies (as long as it's JSON, it's game), and using any secret you need.

On top of all that, it's written in Rust so it's fast and extremely portable (windows, macOS, and linux supported right now).

# Installation

As of right now, the only way to get jwt-cli on your system is by downloading the binary. You can do that from the [release](https://github.com/mike-engel/jwt-cli/releases) page. Eventually I might publish to homebrew and other OS package managers.

Only 64bit linux, macOS, and Windows targets are pre-built. Sorry if you're not on one of those! You'll need to build it from the source. See the [contributing](#contributing) section on how to install and build the project.

# Usage

For usage info, use the `help` command.

```sh
# top level help
jwt help

# command specific help
jwt help encode
```

# Contributing

I welcome all issues and pull requests! This is my first project in rust, so this project almost certainly could be better written. All I ask is that you follow the [code of conduct](code_of_conduct.md) and use [rustfmt](https://github.com/rust-lang-nursery/rustfmt) to have a consistent project code style.

To get started you'll need `rustc` and `cargo` on your system. If they aren't already installed, I recommend [rustup](https://rustup.rs) to get both!

## Running and building the project

Once you have both installed you'll want to install the dependencies.

```sh
# install dependencies via cargo
cargo update
```

After that, I recommend running the tests and doing a debug build to make sure all is well from the start.

```sh
# run the tests
cargo test

# run a debug build
cargo build

# or, if you want, a release build
cargo build --release
```

If it built successfully, you should be able to run the command via `cargo`.

```sh
cargo run -- help
```

# [Code of conduct](code_of_conduct.md)

# [Changelog](CHANGELOG.md)

# [License](LICENSE.md)
