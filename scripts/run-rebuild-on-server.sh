#!/usr/bin/env bash
# Wrapper: strip Windows CRLF then run rebuild-on-server.sh (safe when files were copied from Windows).
exec bash <(tr -d '\r' < "$(dirname "$0")/rebuild-on-server.sh") "$@"
