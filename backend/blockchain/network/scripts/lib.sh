#!/usr/bin/env bash
#
# Shared helpers for the host-side scripts. Sourced, never executed.

# Colours, but only when stdout is a terminal — otherwise escape codes end up in
# log files and CI output where they are noise.
if [[ -t 1 ]]; then
  C_RESET=$'\033[0m'; C_RED=$'\033[31m'; C_GREEN=$'\033[32m'
  C_YELLOW=$'\033[33m'; C_BLUE=$'\033[34m'; C_BOLD=$'\033[1m'
else
  C_RESET=''; C_RED=''; C_GREEN=''; C_YELLOW=''; C_BLUE=''; C_BOLD=''
fi

step() { printf '\n%s==>%s %s%s%s\n' "${C_BLUE}" "${C_RESET}" "${C_BOLD}" "$*" "${C_RESET}"; }
ok()   { printf '%s  ok%s %s\n' "${C_GREEN}" "${C_RESET}" "$*"; }
warn() { printf '%s warn%s %s\n' "${C_YELLOW}" "${C_RESET}" "$*" >&2; }
err()  { printf '%serror%s %s\n' "${C_RED}" "${C_RESET}" "$*" >&2; }

# load_env reads .env and exports the variables the scripts need.
#
# .env is not sourced blindly with `source`: it is parsed line by line so a stray
# command in the file cannot execute. It holds a database password, so it is the
# one file in the repository most likely to be pasted around carelessly.
load_env() {
  local net_dir env_file
  net_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  env_file="${net_dir}/.env"

  if [[ ! -f "${env_file}" ]]; then
    err "${env_file} not found."
    cat >&2 <<EOF

Create it from the template and set a CouchDB password:

    cd ${net_dir}
    cp .env.example .env
    # then edit .env and set COUCHDB_PASSWORD, e.g. to
    #   $(command -v openssl >/dev/null 2>&1 && openssl rand -base64 24 || echo 'output of: openssl rand -base64 24')

EOF
    exit 1
  fi

  local line key value
  while IFS= read -r line || [[ -n "${line}" ]]; do
    line="${line%%$'\r'}"                       # tolerate CRLF from a Windows editor
    [[ -z "${line}" || "${line}" =~ ^[[:space:]]*# ]] && continue
    [[ "${line}" != *=* ]] && continue
    key="${line%%=*}"
    value="${line#*=}"
    key="${key//[[:space:]]/}"
    # Strip one layer of surrounding quotes if present.
    if [[ "${value}" == \"*\" || "${value}" == \'*\' ]]; then
      value="${value:1:${#value}-2}"
    fi
    export "${key}=${value}"
  done < "${env_file}"

  : "${FABRIC_VERSION:?FABRIC_VERSION missing from .env}"
  : "${COUCHDB_VERSION:?COUCHDB_VERSION missing from .env}"
  : "${CHANNEL_NAME:?CHANNEL_NAME missing from .env}"
  : "${CHAINCODE_NAME:?CHAINCODE_NAME missing from .env}"
  : "${CHAINCODE_VERSION:?CHAINCODE_VERSION missing from .env}"
  : "${CHAINCODE_SEQUENCE:?CHAINCODE_SEQUENCE missing from .env}"
  : "${FABRIC_LOGGING_SPEC:=INFO}"

  if [[ -z "${COUCHDB_PASSWORD:-}" ]]; then
    err "COUCHDB_PASSWORD is empty in .env."
    cat >&2 <<'EOF'

The state database holds every medicine record on the channel. Set a real
password — a generated one, not a memorable one:

    openssl rand -base64 24

EOF
    exit 1
  fi

  # A password that survived from the template is not a password.
  case "${COUCHDB_PASSWORD}" in
    password|admin|couchdb|changeme|truemed|test)
      err "COUCHDB_PASSWORD is set to '${COUCHDB_PASSWORD}', which is on every default-credential list in existence."
      err "Generate one: openssl rand -base64 24"
      exit 1
      ;;
  esac
}

# require_docker fails early with an actionable message rather than letting a
# hundred lines of compose output scroll past.
require_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    err "docker not found on PATH."
    err "Install Docker Engine (Linux) or Docker Desktop, then re-run."
    exit 1
  fi
  if ! docker info >/dev/null 2>&1; then
    err "Docker is installed but not responding."
    err "Start the daemon (sudo systemctl start docker), or add yourself to the docker group:"
    err "    sudo usermod -aG docker \$USER   # then log out and back in"
    exit 1
  fi
}

# compose_cmd picks between the plugin and the legacy binary. Both are in the
# wild; hardcoding either breaks on half of all machines.
compose_cmd() {
  if docker compose version >/dev/null 2>&1; then
    echo "docker compose"
  elif command -v docker-compose >/dev/null 2>&1; then
    echo "docker-compose"
  else
    err "Neither 'docker compose' nor 'docker-compose' is available."
    exit 1
  fi
}

# in_cli runs one of the _incontainer scripts inside the CLI container.
#
# The script path is passed to `bash` explicitly rather than executed directly.
# Execute bits do not reliably survive a clone on Windows, a zip round-trip, or a
# OneDrive-synced working copy, and the failure mode is `permission denied` on a
# file that plainly exists — which sends you looking at Docker or at SELinux
# instead of at a file mode. Invoking the interpreter sidesteps the whole class.
in_cli() {
  local script="$1"; shift
  docker exec \
    -e CHANNEL_NAME="${CHANNEL_NAME}" \
    -e CHAINCODE_NAME="${CHAINCODE_NAME}" \
    -e CHAINCODE_VERSION="${CHAINCODE_VERSION}" \
    -e CHAINCODE_SEQUENCE="${CHAINCODE_SEQUENCE}" \
    truemed-cli bash "${script}" "$@"
}

# wait_for_container blocks until a container reports running, with a timeout.
wait_for_container() {
  local name="$1" timeout="${2:-60}" elapsed=0
  while (( elapsed < timeout )); do
    if [[ "$(docker inspect -f '{{.State.Running}}' "${name}" 2>/dev/null)" == "true" ]]; then
      return 0
    fi
    sleep 2
    elapsed=$(( elapsed + 2 ))
  done
  err "${name} did not start within ${timeout}s. Logs:"
  docker logs --tail 40 "${name}" 2>&1 | sed 's/^/    /' >&2 || true
  return 1
}
