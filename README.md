# jwt-cli

[![Dependabot Status](https://api.dependabot.com/badges/status?host=github&repo=mike-engel/jwt-cli)](https://dependabot.com)

A super fast CLI tool to decode and encode JWTs built in [Rust](https://rust-lang.org).

[![Build Status](https://travis-ci.org/mike-engel/jwt-cli.svg?branch=master)](https://travis-ci.org/mike-engel/jwt-cli)
[![Build status](https://ci.appveyor.com/api/projects/status/9p1lqbo8cmhixdns/branch/master?svg=true)](https://ci.appveyor.com/project/mike-engel/jwt-cli/branch/master)
[![GitHub release](https://img.shields.io/github/tag/mike-engel/jwt-cli.svg)]()

`jwt-cli` is a command line tool to help you work with JSON Web Tokens (JWTs). Like most JWT command line tools out there, you can decode almost any JWT header and claims body. Unlike any that I've found, however, `jwt-cli` allows you to encode a new JWT with nearly any piece of data you can think of. Custom header values (some), custom claim bodies (as long as it's JSON, it's game), and using any secret you need.

On top of all that, it's written in Rust so it's fast and extremely portable (windows, macOS, and linux supported right now).

# Installation

Currently, installation is supported via [Homebrew](https://brew.sh) (macOS), [Cargo](https://www.rust-lang.org/tools/install) (cross-platform), and [FreshPorts](https://www.freshports.org/www/jwt-cli) (FreeBSD). If you intend to use one of these methods, [skip ahead](#homebrew).

You may also install the binary from the [release](https://github.com/mike-engel/jwt-cli/releases) page, if you're unable to use Homebrew or Cargo install methods below.

Only 64bit linux, macOS, and Windows targets are pre-built. Sorry if you're not on one of those! You'll need to build it from the source. See the [contributing](#contributing) section on how to install and build the project.

As to where you should install it, it should optimally go somewhere in your `PATH`. For Linux and macOS, a good place is generally `/usr/local/bin`. For Windows, there really isn't a good place by default :(.

## Homebrew

For those with Homebrew, you'll need to `brew tap mike-engel/jwt-cli` repo in order to install it.

```sh
# Tap and install jwt-cli
brew tap mike-engel/jwt-cli
brew install jwt-cli

# Ensure it worked ok by running the help command
jwt help
```

## Cargo

If your system [supports](https://forge.rust-lang.org/platform-support.html) it, you can install via Cargo. Make sure you have Rust and Cargo installed, following [these instructions](https://www.rust-lang.org/tools/install) before proceeding.

```sh
cargo install jwt-cli
```

The binary will be installed in your Cargo bin path (`~/.cargo/bin`). Make sure this path is included in your PATH environment variable.

## FreshPorts

If you're on FreeBSD, you can use the `pkg` tool to install `jwt-cli` on your system.

```sh
pkg install jwt-cli
```

Big thanks to Sergey Osokin, the FreeBSD contributor who added `jwt-cli` to the FreeBSD ports tree!

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

## Contributors ✨

Thanks goes to these wonderful people ([emoji key](https://allcontributors.org/docs/en/emoji-key)):

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore -->
<table>
  <tr>
    <td align="center"><a href="https://www.mike-engel.com"><img src="https://avatars0.githubusercontent.com/u/464447?v=4" width="100px;" alt="Mike Engel"/><br /><sub><b>Mike Engel</b></sub></a><br /><a href="https://github.com/mike-engel/jwt-cli/commits?author=mike-engel" title="Code">💻</a> <a href="#question-mike-engel" title="Answering Questions">💬</a> <a href="https://github.com/mike-engel/jwt-cli/commits?author=mike-engel" title="Documentation">📖</a> <a href="#ideas-mike-engel" title="Ideas, Planning, & Feedback">🤔</a> <a href="#maintenance-mike-engel" title="Maintenance">🚧</a> <a href="#review-mike-engel" title="Reviewed Pull Requests">👀</a> <a href="https://github.com/mike-engel/jwt-cli/commits?author=mike-engel" title="Tests">⚠️</a> <a href="https://github.com/mike-engel/jwt-cli/issues?q=author%3Amike-engel" title="Bug reports">🐛</a></td>
    <td align="center"><a href="http://asymmetrical-view.com/"><img src="https://avatars0.githubusercontent.com/u/69799?v=4" width="100px;" alt="Kyle Burton"/><br /><sub><b>Kyle Burton</b></sub></a><br /><a href="https://github.com/mike-engel/jwt-cli/commits?author=kyleburton" title="Code">💻</a></td>
    <td align="center"><a href="https://github.com/atschaef"><img src="https://avatars2.githubusercontent.com/u/6707250?v=4" width="100px;" alt="Aaron Schaef"/><br /><sub><b>Aaron Schaef</b></sub></a><br /><a href="https://github.com/mike-engel/jwt-cli/commits?author=atschaef" title="Code">💻</a></td>
    <td align="center"><a href="https://github.com/hughsimpson"><img src="https://avatars2.githubusercontent.com/u/2494489?v=4" width="100px;" alt="hughsimpson"/><br /><sub><b>hughsimpson</b></sub></a><br /><a href="https://github.com/mike-engel/jwt-cli/commits?author=hughsimpson" title="Code">💻</a> <a href="https://github.com/mike-engel/jwt-cli/commits?author=hughsimpson" title="Tests">⚠️</a></td>
    <td align="center"><a href="http://matkelly.com"><img src="https://avatars0.githubusercontent.com/u/2514780?v=4" width="100px;" alt="Mat Kelly"/><br /><sub><b>Mat Kelly</b></sub></a><br /><a href="https://github.com/mike-engel/jwt-cli/commits?author=machawk1" title="Code">💻</a> <a href="https://github.com/mike-engel/jwt-cli/issues?q=author%3Amachawk1" title="Bug reports">🐛</a></td>
    <td align="center"><a href="http://www.jasonmfry.com"><img src="https://avatars3.githubusercontent.com/u/166681?v=4" width="100px;" alt="Jason"/><br /><sub><b>Jason</b></sub></a><br /><a href="https://github.com/mike-engel/jwt-cli/issues?q=author%3AJasonMFry" title="Bug reports">🐛</a></td>
    <td align="center"><a href="https://crosscomm.com/"><img src="https://avatars1.githubusercontent.com/u/6886697?v=4" width="100px;" alt="Ben Berry"/><br /><sub><b>Ben Berry</b></sub></a><br /><a href="https://github.com/mike-engel/jwt-cli/issues?q=author%3Absberry" title="Bug reports">🐛</a></td>
  </tr>
  <tr>
    <td align="center"><a href="https://medium.com/@therealklanni"><img src="https://avatars2.githubusercontent.com/u/626347?v=4" width="100px;" alt="Kevin Lanni"/><br /><sub><b>Kevin Lanni</b></sub></a><br /><a href="https://github.com/mike-engel/jwt-cli/commits?author=therealklanni" title="Documentation">📖</a></td>
  </tr>
</table>

<!-- ALL-CONTRIBUTORS-LIST:END -->

This project follows the [all-contributors](https://github.com/all-contributors/all-contributors) specification. Contributions of any kind welcome!
