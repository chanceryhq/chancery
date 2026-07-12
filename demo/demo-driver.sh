#!/bin/bash
# Self-typing demo driver for asciinema. ~75 seconds.
set -e
export CHANCERY_DATA="$(mktemp -d)"
G=$'\033[32m'; D=$'\033[2m'; R=$'\033[0m'; B=$'\033[1m'

type_out(){ # simulate typing
  local s="$1"
  printf '%s' "${G}❯${R} "
  for ((i=0;i<${#s};i++)); do printf '%s' "${s:$i:1}"; sleep 0.018; done
  printf '\n'; sleep 0.25
}
run(){ type_out "$1"; eval "$1"; sleep "${2:-1.6}"; }
say(){ sleep 0.4; printf '%s\n' "${D}# $1${R}"; sleep "${2:-1.2}"; }

clear
printf '%s\n' "${B}Chancery — the identity provider for AI agents${R}"
say "install: brew install chanceryhq/tap/chancery" 1.5

run "chancery init --trust-domain acme.com" 1.8
run "chancery agent register deploy-bot --owner user:aneesh@acme.com --purpose 'deploys services'" 1.6

say "give it authority — scoped, signed, expiring"
W=$(chancery writ grant --for user:aneesh@acme.com --to deploy-bot --cap "call:github/*" | awk '/^writ /{print $2}')
type_out "chancery writ grant --for user:aneesh@acme.com --to deploy-bot --cap 'call:github/*'"
chancery writ show "$W" 2>/dev/null || chancery writ list; sleep 1.8

run "chancery writ check $W --resource github/merge_pull" 2.0

say "security learns its prompt was changed outside review. one command:" 1.4
run "chancery writ revoke $W" 1.4
run "chancery writ check $W --resource github/merge_pull" 2.2

say "every step above is already on the record — and the record is tamper-evident"
run "chancery audit --limit 6" 2.4
run "chancery audit verify" 2.2

say "dashboard: chancery serve → http://127.0.0.1:7423/ui  (read-only, embedded)" 2.0
printf '%s\n' "${B}github.com/chanceryhq/chancery${R}"
sleep 2
