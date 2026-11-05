#!/usr/bin/env bash
#
# TrueMed — network control.
#
#   ./network.sh up        generate crypto if needed, start containers, create the channel
#   ./network.sh deploy    vendor, package, install, approve and commit the chaincode
#   ./network.sh test      end-to-end smoke test against the deployed chaincode
#   ./network.sh down      stop everything and delete the data volumes
#   ./network.sh restart   down, then up, then deploy
#   ./network.sh status    what is running, and on which ports
#   ./network.sh logs [c]  follow logs, optionally for one container
#
# The happy path from a clean checkout is three commands:
#
#   cp .env.example .env && $EDITOR .env     # set COUCHDB_PASSWORD
#   ./scripts/network.sh up
#   ./scripts/network.sh deploy && ./scripts/network.sh test

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NET_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# shellcheck source=/dev/null
source "${SCRIPT_DIR}/lib.sh"

COMPOSE=""

network_up() {
  require_docker
  load_env
  COMPOSE="$(compose_cmd)"

  if [[ ! -d "${NET_DIR}/organizations" ]]; then
    step "No crypto material found — generating it first"
    bash "${SCRIPT_DIR}/generate.sh"
  fi

  step "Starting containers"
  ( cd "${NET_DIR}" && ${COMPOSE} up -d )

  step "Waiting for nodes"
  for container in orderer.truemed.in \
                   peer0.manufacturer.truemed.in \
                   peer0.distributor.truemed.in \
                   peer0.regulator.truemed.in \
                   truemed-cli; do
    wait_for_container "${container}" 120
    ok "${container}"
  done

  # The orderer accepts connections a moment before it is ready to serve the
  # admin API. Joining too early fails with a bare connection error, which reads
  # like a TLS problem and sends you looking in the wrong place.
  sleep 5

  step "Creating channel '${CHANNEL_NAME}'"
  in_cli /opt/truemed/scripts/_incontainer/create-channel.sh

  cat <<EOF

${C_GREEN}Network is up.${C_RESET}

  orderer      localhost:7050   (admin 7053, metrics 9443)
  manufacturer localhost:7051   (metrics 9444)
  distributor  localhost:9051   (metrics 9445)
  regulator    localhost:11051  (metrics 9446)
  couchdb      127.0.0.1:5984 / 6984 / 7984   (localhost only, by design)

Next:  ./scripts/network.sh deploy

EOF
}

network_deploy() {
  require_docker
  load_env
  COMPOSE="$(compose_cmd)"

  local cc_dir="${NET_DIR}/../chaincode"

  # Vendoring happens on the host side, in a Go container, because the peer builds
  # chaincode in a sandbox with no network access. Without vendor/ the build fails
  # partway through with a module download error that looks like a proxy problem.
  step "Vendoring Go dependencies"
  local user_flag=()
  command -v id >/dev/null 2>&1 && user_flag=(--user "$(id -u):$(id -g)")
  docker run --rm "${user_flag[@]}" \
    -v "$(cd "${cc_dir}" && pwd):/src" -w /src \
    -e GOCACHE=/tmp/gocache -e GOPATH=/tmp/gopath -e GOFLAGS=-mod=mod \
    golang:1.21 \
    sh -c 'go mod tidy && go mod vendor'
  ok "vendor/ is populated"

  step "Running the rule tests before deploying"
  docker run --rm "${user_flag[@]}" \
    -v "$(cd "${cc_dir}" && pwd):/src" -w /src \
    -e GOCACHE=/tmp/gocache -e GOPATH=/tmp/gopath \
    golang:1.21 \
    go test ./internal/rules/...
  ok "business rules pass"

  step "Deploying chaincode '${CHAINCODE_NAME}' v${CHAINCODE_VERSION} seq ${CHAINCODE_SEQUENCE}"
  in_cli /opt/truemed/scripts/_incontainer/deploy-cc.sh

  cat <<EOF

${C_GREEN}Chaincode committed.${C_RESET}

Next:  ./scripts/network.sh test

EOF
}

network_test() {
  require_docker
  load_env
  step "Smoke test"
  in_cli /opt/truemed/scripts/_incontainer/smoke-test.sh
}

network_down() {
  require_docker
  load_env
  COMPOSE="$(compose_cmd)"

  step "Stopping containers and removing volumes"
  ( cd "${NET_DIR}" && ${COMPOSE} down --volumes --remove-orphans )

  # Chaincode containers are launched by the peer, not by Compose, so `compose
  # down` leaves them behind. A stale one from a previous build will happily
  # attach to the new network and serve the old logic, which is a genuinely
  # baffling bug to chase.
  step "Removing chaincode containers and images"
  local stale
  stale="$(docker ps -aq --filter "name=dev-peer0" 2>/dev/null || true)"
  if [[ -n "${stale}" ]]; then
    docker rm -f ${stale} >/dev/null
    ok "removed $(wc -w <<< "${stale}") chaincode container(s)"
  fi
  stale="$(docker images -q --filter "reference=dev-peer0*" 2>/dev/null || true)"
  if [[ -n "${stale}" ]]; then
    docker rmi -f ${stale} >/dev/null 2>&1 || true
    ok "removed chaincode image(s)"
  fi

  rm -rf "${NET_DIR}/channel-artifacts"

  cat <<EOF

Containers, volumes and chaincode images are gone.

Crypto material in organizations/ was KEPT, so 'up' will reuse the same
identities. To start from nothing:

    rm -rf ${NET_DIR}/organizations

EOF
}

network_status() {
  require_docker
  printf '\n%sTrueMed containers%s\n\n' "${C_BOLD}" "${C_RESET}"
  docker ps \
    --filter "name=truemed" --filter "name=orderer.truemed.in" \
    --filter "name=peer0." --filter "name=couchdb-" \
    --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
  printf '\n'
}

network_logs() {
  require_docker
  load_env
  COMPOSE="$(compose_cmd)"
  if [[ $# -gt 0 ]]; then
    docker logs -f --tail 100 "$1"
  else
    ( cd "${NET_DIR}" && ${COMPOSE} logs -f --tail 50 )
  fi
}

usage() {
  sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

case "${1:-}" in
  up)      network_up ;;
  deploy)  network_deploy ;;
  test)    network_test ;;
  down)    network_down ;;
  restart) network_down; network_up; network_deploy ;;
  status)  network_status ;;
  logs)    shift; network_logs "$@" ;;
  ""|-h|--help|help) usage ;;
  *)       err "Unknown command: $1"; usage; exit 1 ;;
esac
