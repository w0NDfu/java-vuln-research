#!/usr/bin/env bash
set -euo pipefail
umask 077
root=$(cd -- "$(dirname -- "$0")" && pwd)
base=$(realpath "$root/..")
previous="$base/experiments/work1-m7-source-only-20261108"
python="$base/.venv/bin/python"
variant=${WORK1_VARIANT_DIR:-work}
case "$variant" in work|enhanced) ;; *) exit 2;; esac
work="$root/$variant"
export PYTHONPATH="$work/code/src:$previous/test-deps:$base/experiments/library-repair-20261019/reproduction"
export PYTHONDONTWRITEBYTECODE=1
test "$#" -eq 1
job="$root/$1"
case "$1" in ""|*[!a-zA-Z0-9_-]*) exit 2;; esac
mkdir "$job"
(
    cd "$work"
    find code/src -type f -name '*.py' -print0 | sort -z | xargs -0 sha256sum
    sha256sum run_complete.py score_single.py "$root/launch.sh"
) > "$job/variant.sha256"
"$python" -B "$work/run_complete.py" "$base" "$previous" --preflight > "$job/preflight.json"
nohup bash -c '
    set +e
    python=$1
    work=$2
    base=$3
    previous=$4
    job=$5
    "$python" -B "$work/run_complete.py" "$base" "$previous" "$job"
    rc=$?
    printf "%s\n" "$rc" > "$job/exit-code.tmp"
    mv -T "$job/exit-code.tmp" "$job/exit-code"
    if [ "$rc" -eq 0 ]; then
        "$python" -B "$work/score_single.py" "$base" "$job" > "$job/scorer.log" 2>&1
        printf "%s\n" "$?" > "$job/scorer-exit-code"
    fi
    exit "$rc"
' _ "$python" "$work" "$base" "$previous" "$job" </dev/null >"$job/runner.log" 2>&1 &
printf '%s\n' "$!" > "$job/pid"
printf '%s\n' "$job"
