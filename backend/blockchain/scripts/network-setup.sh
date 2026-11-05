#!/usr/bin/env bash
# TrueMed — generate crypto, start the Fabric network, create the channel.
#
# The live compose file, crypto-config and configtx live under blockchain/network/
# because a three-organisation channel (Manufacturer, Distributor, Regulator) is
# required by docs/DATA-CONTRACT.md §3.4. This wrapper is the entry point named
# in the component brief.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec bash "${ROOT}/network/scripts/network.sh" up "$@"
