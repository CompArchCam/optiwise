#!/bin/sh -u
#
# Script that redirects stdin, stdout and stderr for a program.
#
# This is used as a wrapper for sampled programs in order to allow us to
# separate the stdout and stderr for the program from any sampling utility (i.e.
# perf).

if [ $# -lt 4 ]; then
  cat >&2 <<EOF
Error: incorrect arguments to $0

Usage:
$0 <stdin> <stdout> <stderr> <command> [<arguments>]
EOF
  exit 1
fi
stdin="$1"
shift
stdout="$1"
shift
stderr="$1"
shift
# Note: use exec here so we get the same PID
exec "$@" < "$stdin" > "$stdout" 2> "$stderr"
