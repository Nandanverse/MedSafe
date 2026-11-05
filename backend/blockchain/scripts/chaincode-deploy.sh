#!/usr/bin/env bash
# TrueMed — vendor, package, install, approve and commit the chaincode.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec bash "${ROOT}/network/scripts/network.sh" deploy "$@"
