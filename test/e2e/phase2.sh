#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Phase 2 e2e: container scoping and process lineage.
# Run from the repo root as root, after `make build`: sudo test/e2e/phase2.sh
set -uo pipefail

SENSOR=${SENSOR:-./anyone-sensor}
NAME=as-e2e-phase2
WORK=$(mktemp -d)
OUT=$WORK/events.jsonl
ERR=$WORK/sensor.err
PID=
FAILS=0

pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; FAILS=$((FAILS + 1)); }
since() { tail -n +"$(($1 + 1))" "$OUT"; }
lines() { wc -l <"$OUT"; }

start_sensor() {
	"$SENSOR" -container "$NAME" >>"$OUT" 2>>"$ERR" &
	PID=$!
	for _ in $(seq 50); do grep -q "seeded process table" "$ERR" 2>/dev/null && return 0; sleep 0.1; done
	echo "sensor did not start:"; cat "$ERR"; exit 1
}
stop_sensor() { [ -n "$PID" ] && kill -INT "$PID" 2>/dev/null && wait "$PID" 2>/dev/null; PID=; }
cleanup() { stop_sensor; docker rm -f "$NAME" >/dev/null 2>&1; echo "artifacts: $WORK"; }
trap cleanup EXIT

[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
[ -x "$SENSOR" ] || { echo "$SENSOR not found; run make build"; exit 1; }
command -v jq >/dev/null || { echo "jq required"; exit 1; }

docker rm -f "$NAME" >/dev/null 2>&1
docker run -d --name "$NAME" alpine sh -c 'while true; do sleep 1; done' >/dev/null
sleep 1
start_sensor

echo "== 1. host activity is not captured in container mode"
n=$(lines)
ls /tmp >/dev/null; /bin/true; bash -c 'echo host' >/dev/null
sleep 1.5
if since "$n" | jq -e -s 'all(.container != null)' >/dev/null &&
	! since "$n" | jq -e -s 'any(.process.argv == ["bash","-c","echo host"])' >/dev/null; then
	pass "no host events (all $(since "$n" | wc -l) new events belong to the container)"
else
	fail "host events leaked into container mode"
fi

echo "== 2. docker exec lineage"
n=$(lines)
docker exec "$NAME" sh -c 'sleep 1'
sleep 1
since "$n" >"$WORK/exec.jsonl"
if jq -e -s 'any(.type == "exec" and .process.argv == ["sh","-c","sleep 1"]
	and .parent.known and .parent.external
	and (.parent.image | test("containerd-shim")))' "$WORK/exec.jsonl" >/dev/null; then
	pass "sh -c 'sleep 1' captured; parent is containerd-shim (external, outside the container)"
else
	fail "docker exec sh not captured with containerd-shim parent"
fi
if jq -e -s '(map(select(.process.argv == ["sh","-c","sleep 1"]))[0].process.guid) as $g
	| any(.type == "exit" and .process.guid == $g and .exit.code == 0)' "$WORK/exec.jsonl" >/dev/null; then
	pass "exit event with code 0 for the same process GUID"
else
	fail "no exit event for the docker exec process"
fi

echo "== 3. container restart"
old=$(jq -r 'select(.container) | .process.cgroup_id' "$OUT" | tail -1)
docker restart -t 1 "$NAME" >/dev/null
sleep 3
first_new=$(jq -s --argjson old "$old" 'map(select(.process.cgroup_id != $old)) | .[0].timestamp_ns // empty' "$OUT")
last_old=$(jq -s --argjson old "$old" 'map(select(.process.cgroup_id == $old)) | .[-1].timestamp_ns' "$OUT")
if [ -n "$first_new" ]; then
	gap_ms=$(((first_new - last_old) / 1000000))
	echo "      last event in old cgroup -> first event in new cgroup: ${gap_ms} ms"
	if [ "$gap_ms" -lt 2000 ]; then pass "events resumed within 2 s (${gap_ms} ms)"; else fail "gap ${gap_ms} ms >= 2 s"; fi
else
	fail "no events after restart"
fi
if jq -e -s --argjson old "$old" 'any(.type == "exec" and .process.cgroup_id != $old
	and .process.argv[0:2] == ["sh","-c"])' "$OUT" >/dev/null; then
	pass "entrypoint exec of the restarted container was captured"
else
	fail "entrypoint exec of the restarted container was missed"
fi
grep -q 'via="inotify cgroup create"' "$ERR" && pass "new cgroup picked up via inotify" || fail "new cgroup not picked up via inotify"

echo "== 4. sensor restart re-seeds lineage"
stop_sensor
n=$(lines)
start_sensor
docker exec "$NAME" sh -c 'sleep 1; id' >/dev/null
sleep 3
since "$n" >"$WORK/reseed.jsonl"
if jq -e -s 'length > 0 and all(.parent.known)' "$WORK/reseed.jsonl" >/dev/null; then
	pass "no orphan parents after sensor restart ($(wc -l <"$WORK/reseed.jsonl") events)"
else
	fail "orphan parents after sensor restart:"
	jq -c 'select(.parent.known | not) | {type, pid: .process.pid, argv: .process.argv, ppid: .parent.pid}' "$WORK/reseed.jsonl" | head -5
fi
if jq -e -s 'any(.type == "exec" and .process.argv == ["sleep","1"]
	and .parent.argv == ["sh","-c","while true; do sleep 1; done"])' "$WORK/reseed.jsonl" >/dev/null; then
	pass "init loop's children link to the init process seeded from /proc"
else
	fail "init loop's children not linked to seeded init"
fi

echo
if [ "$FAILS" -eq 0 ]; then echo "phase2: all checks passed"; else echo "phase2: $FAILS check(s) failed"; fi
exit "$FAILS"
