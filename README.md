# luigis-mansion-3

NEX game server for **Luigi's Mansion 3**, built on the NextendoNetwork [nextendo-nex](https://github.com/NextendoNetwork/nextendo-nex) core. Source only — no binaries, no certs. Not affiliated with Nintendo.

## Build

Clone this repo and `nextendo-nex` side by side (the `go.mod` `replace` directive points at `../nextendo-nex`), then:

    go build ./...

See `example.env` for configuration.

## Credits

Luigi's Mansion 3 server implementation by [**@LITTLECHOPT8**](https://github.com/LITTLECHOPT8).

Hardened for production by the NextendoNetwork maintainers: signed-token identity gate (anti-impersonation), leaked-token denylist, fail-closed internal endpoints, and bounded NAT/presence state.
