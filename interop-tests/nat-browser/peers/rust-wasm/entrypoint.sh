#!/bin/sh
# Maps the harness's uniform `listener` / `dialer` argument onto the env interface
# of the rust wasm interop wrapper (`wasm_ping` reads `is_dialer` et al, spawns
# chromedriver + headless Chrome and serves the embedded wasm bundle to it).
set -eu

mode="${1:-${MODE:-}}"
case "${mode#--}" in
    listener|listen)
        export is_dialer=false
        ;;
    dialer|dial)
        export is_dialer=true
        ;;
    "")
        # No mode given: rely on the `is_dialer` env var.
        ;;
    *)
        echo "unknown mode '${mode}', expected listener | dialer" >&2
        exit 2
        ;;
esac

exec /usr/local/bin/wasm_ping
