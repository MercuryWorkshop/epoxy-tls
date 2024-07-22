# `epoxy-server`
Performant server implementation of the Wisp protocol in Rust, made for epoxy.

You can view a recent flamegraph of the server under load [here](flamegraph.svg?raw=true).

## Configuration
`epoxy-server` is configured through a configuration file in either TOML, JSON, or YAML. Pass the configuration file's path as an argument to `epoxy-server`.

The defaults can be printed with the command line option `--default-config` and the configuration file format can be changed from the default of TOML with the command line option `--format`. Documentation for the available configuration options is in [`src/config.rs`](src/config.rs).
