#!/bin/sh
# Pull digest-pinned scanner images for local Compose (docker-out-of-Docker).
# Used by the compose `scanner-pull` one-shot service.
set -eu

pull_one() {
  name="$1"
  img="$2"
  zeros="0000000000000000000000000000000000000000000000000000000000000000"
  case "$img" in
    "")
      echo "ERROR: ATTESTRA_IMAGE_${name} is empty" >&2
      exit 1
      ;;
    *"@sha256:${zeros}")
      echo "ERROR: ATTESTRA_IMAGE_${name} is still a placeholder digest" >&2
      exit 1
      ;;
    *"@sha256:"*)
      ;;
    *)
      echo "ERROR: ATTESTRA_IMAGE_${name} must be digest-pinned (repo@sha256:...): $img" >&2
      exit 1
      ;;
  esac
  echo "Pulling ${name}: ${img}"
  docker pull "$img"
}

pull_one ZAP "${ATTESTRA_IMAGE_ZAP}"
pull_one NUCLEI "${ATTESTRA_IMAGE_NUCLEI}"
pull_one TESTSSL "${ATTESTRA_IMAGE_TESTSSL}"
pull_one NAABU "${ATTESTRA_IMAGE_NAABU}"
echo "All scanner images ready."
