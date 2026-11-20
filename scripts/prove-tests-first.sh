#!/usr/bin/env bash
# Proves from git history that each tests/sNN_*.rs failed before the code that made it pass.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RED_LIST=tests/expected-red.txt
RED_RUNS=proof/red-runs
RED_RUN_ALL=proof/red-run.txt
REPLAY_ROOT=target/prove-tests-first
STEM_RE='^s[0-9]{2}_[A-Za-z0-9_]+$'
# Smoke tests written in the commit that added the crate skeleton (src/lib.rs).
SKELETON_STEMS="s01_install s29_restart"
EXPORT=""
CARGO_STATUS=0
VERDICT=""
RUN_KIND=none
RUN_SOURCE=""
RUN_LINE=""
RUN_FAILED=0
RUN_BUILD_FAILED=0

fail() {
    echo "PROVE-TESTS-FIRST FAIL: $*" >&2
    exit 1
}

# Removes the exported tree of a replay if one is still there.
cleanup() {
    if [[ -n "$EXPORT" ]]; then
        rm -rf -- "$EXPORT"
    fi
}
trap cleanup EXIT

cd "$ROOT"
git rev-parse --verify --quiet HEAD >/dev/null || fail "no commit at HEAD"

# Prints the test stems at HEAD (tests/sNN_*.rs), one per line, in name order.
head_stems() {
    git ls-tree -r --name-only HEAD -- tests/ \
        | sed -n 's#^tests/\(s[0-9][0-9]_[A-Za-z0-9_]*\)\.rs$#\1#p' \
        | LC_ALL=C sort
}

# Prints the oldest commit that added tests/STEM.rs; prints nothing when none did.
added_commit() {
    git log --no-renames --diff-filter=A --format=%H -- "tests/$1.rs" | tail -n 1
}

# Succeeds when the expected-red list at commit $1 names the stem $2.
listed_at() {
    local stems=""
    if git cat-file -e "$1:$RED_LIST" 2>/dev/null; then
        stems="$(git show "$1:$RED_LIST" | awk '!/^[[:space:]]*#/ && NF { print $1 }')"
    fi
    grep -qxF -- "$2" <<<"$stems"
}

# Prints the first commit after $1 whose list no longer names the stem $2, or nothing.
landed_commit() {
    local commit
    while read -r commit; do
        if ! listed_at "$commit" "$2"; then
            printf '%s\n' "$commit"
            return 0
        fi
    done < <(git log --reverse --format=%H "$1..HEAD" -- "$RED_LIST")
    return 0
}

# Succeeds when the stem $1 is a crate skeleton smoke test: named in SKELETON_STEMS and added by the commit that added src/lib.rs.
is_skeleton() {
    local stem="$1" add lib_add
    case " $SKELETON_STEMS " in
        *" $stem "*) ;;
        *) return 1 ;;
    esac
    add="$(added_commit "$stem")"
    lib_add="$(git log --no-renames --diff-filter=A --format=%H -- src/lib.rs | tail -n 1)"
    [[ -n "$add" && "$add" == "$lib_add" ]]
}

# Prints "FOUND OK FAILED" for the Running section of the stem $2 in the file $1.
section_counts() {
    awk -v stem="$2" '
        /^ +(Running|Doc-tests) / { inside = index($0, "Running tests/" stem ".rs (") > 0; found += inside; next }
        inside && / \.\.\. ok$/ { ok++ }
        inside && / \.\.\. FAILED$/ { failed++ }
        END { print found + 0, ok + 0, failed + 0 }
    ' "$1"
}

# Sets RUN_KIND, RUN_SOURCE, RUN_LINE, RUN_FAILED and RUN_BUILD_FAILED for the stem $1.
find_run() {
    local stem="$1" found=0 ok=0 failed=0 results=0 nocompile=0
    RUN_KIND=none
    RUN_SOURCE=""
    RUN_FAILED=0
    RUN_BUILD_FAILED=0
    RUN_LINE="none saved (run --replay $stem)"
    if [[ -f "$RED_RUNS/$stem.txt" ]]; then
        read -r ok failed results nocompile < <(awk '
            / \.\.\. ok$/ { ok++ }
            / \.\.\. FAILED$/ { failed++ }
            /^test result:/ { results++ }
            /could not compile/ { nocompile++ }
            END { print ok + 0, failed + 0, results + 0, nocompile + 0 }
        ' "$RED_RUNS/$stem.txt")
        RUN_KIND=saved
        RUN_SOURCE="$RED_RUNS/$stem.txt"
        if (( results == 0 && nocompile > 0 )); then
            RUN_BUILD_FAILED=1
            RUN_LINE="$RUN_SOURCE: did not build"
            return 0
        fi
    elif [[ -f "$RED_RUN_ALL" ]]; then
        read -r found ok failed < <(section_counts "$RED_RUN_ALL" "$stem")
        if (( found > 0 )); then
            RUN_KIND=saved
            RUN_SOURCE="$RED_RUN_ALL"
        fi
    fi
    if [[ $RUN_KIND == saved ]]; then
        RUN_FAILED=$failed
        RUN_LINE="$RUN_SOURCE: $((ok + failed)) tests, $failed failed"
    fi
}

# Succeeds when the saved run found by find_run has no failed test and did not fail to build.
saved_run_has_no_failure() {
    [[ $RUN_KIND == saved && $RUN_FAILED -eq 0 && $RUN_BUILD_FAILED -eq 0 ]]
}

# Prints the block for the stem $1 and sets VERDICT and the RUN_* variables.
report_block() {
    local stem="$1" add short subject landed count listed=no
    add="$(added_commit "$stem")"
    [[ -n "$add" ]] || fail "no commit added tests/$stem.rs"
    short="$(git log -1 --format=%h "$add")"
    subject="$(git log -1 --format=%s "$add")"
    printf '%s\n' "$stem"
    if is_skeleton "$stem"; then
        printf '  %-14s %s %s\n' "test added:" "$short" "$subject"
        printf '  %-14s no, written in the same commit as the crate skeleton it tests\n' "listed red:"
        printf '  %-14s %s (the same commit)\n' "code landed:" "$short"
        find_run "$stem"
        printf '  %-14s %s\n' "run at add:" "$RUN_LINE"
        VERDICT="WRITTEN WITH THE SKELETON"
        printf '  %-14s %s\n' "verdict:" "$VERDICT"
        return 0
    fi
    if listed_at "$add" "$stem"; then
        listed=yes
    fi
    printf '  %-14s %s %s\n' "test added:" "$short" "$subject"
    if [[ $listed == yes ]]; then
        printf '  %-14s yes, from %s\n' "listed red:" "$short"
        landed="$(landed_commit "$add" "$stem")"
        if [[ -n "$landed" ]]; then
            count="$(git rev-list --count "$add..$landed")"
            printf '  %-14s %s %s   (%s commits later)\n' "code landed:" \
                "$(git log -1 --format=%h "$landed")" "$(git log -1 --format=%s "$landed")" "$count"
        else
            printf '  %-14s still expected to fail\n' "code landed:"
        fi
    else
        printf '  %-14s no\n' "listed red:"
        printf '  %-14s n/a, not listed red when added\n' "code landed:"
    fi
    find_run "$stem"
    printf '  %-14s %s\n' "failing run:" "$RUN_LINE"
    VERDICT="TESTS FIRST"
    if [[ $listed != yes ]]; then
        VERDICT="NOT LISTED RED WHEN ADDED"
    elif saved_run_has_no_failure; then
        VERDICT="SAVED RUN DID NOT FAIL"
    fi
    printf '  %-14s %s\n' "verdict:" "$VERDICT"
}

# Prints one block per test file at HEAD and the totals; exits 1 when a file is not tests-first.
report_all() {
    local stem total=0 tests_first=0 skeleton=0 not_first=0 unsaved=0 zero_runs=0
    local -a stems
    mapfile -t stems < <(head_stems)
    (( ${#stems[@]} > 0 )) || fail "no tests/sNN_*.rs at HEAD"
    for stem in "${stems[@]}"; do
        report_block "$stem"
        total=$((total + 1))
        case "$VERDICT" in
            "TESTS FIRST") tests_first=$((tests_first + 1)) ;;
            "WRITTEN WITH THE SKELETON") skeleton=$((skeleton + 1)) ;;
            *) not_first=$((not_first + 1)) ;;
        esac
        if [[ $RUN_KIND == none ]]; then
            unsaved=$((unsaved + 1))
        elif [[ $VERDICT != "WRITTEN WITH THE SKELETON" ]] && saved_run_has_no_failure; then
            zero_runs=$((zero_runs + 1))
        fi
    done
    echo "$total test files: $tests_first tests first, $skeleton written with the crate skeleton, $not_first not"
    echo "$unsaved without a saved failing run"
    if (( not_first > 0 || zero_runs > 0 )); then
        echo "PROVE-TESTS-FIRST FAIL"
        exit 1
    fi
    echo "PROVE-TESTS-FIRST PASS"
}

# Writes the header and the cargo test output of stem $2 (exported at $4) to the file $1.
# Arguments after the fourth are cargo flags; the exit status is left in CARGO_STATUS.
run_cargo_test() {
    local saved="$1" stem="$2" short="$3" dir="$4"
    shift 4
    printf '# Red run of %s at %s\n' "$stem" "$short" >"$saved"
    CARGO_STATUS=0
    (cd "$dir" && CARGO_TARGET_DIR="$ROOT/$REPLAY_ROOT/build" cargo test "$@" --test "$stem" --no-fail-fast) \
        >>"$saved" 2>&1 || CARGO_STATUS=$?
}

# Replays the red run of the stem $1 at the commit that added it; returns 0 when red, 1 when not.
replay_one() {
    local stem="$1" add short saved lock_size ok=0 failed=0 total
    local -a locked=()
    add="$(added_commit "$stem")"
    [[ -n "$add" ]] || fail "no commit added tests/$stem.rs"
    short="$(git log -1 --format=%h "$add")"
    saved="$ROOT/$RED_RUNS/$stem.txt"
    EXPORT="$ROOT/$REPLAY_ROOT/$short"
    rm -rf -- "$EXPORT"
    mkdir -p -- "$EXPORT"
    git archive "$add" | tar -x -C "$EXPORT"
    echo "exported $short to $REPLAY_ROOT/$short"
    lock_size="$(git cat-file -s "$add:Cargo.lock" 2>/dev/null || echo 0)"
    if (( lock_size > 0 )); then
        locked=(--locked)
        echo "$short: Cargo.lock present, cargo test runs with --locked"
    else
        echo "$short: no Cargo.lock, cargo test runs without --locked"
    fi
    mkdir -p -- "$ROOT/$RED_RUNS"
    run_cargo_test "$saved" "$stem" "$short" "$EXPORT" ${locked[@]+"${locked[@]}"}
    if (( CARGO_STATUS != 0 && ${#locked[@]} > 0 )) && grep -q -- '--locked was passed' "$saved"; then
        echo "$short: Cargo.lock does not match its manifest, rerunning without --locked"
        locked=()
        run_cargo_test "$saved" "$stem" "$short" "$EXPORT"
    fi
    rm -rf -- "$EXPORT"
    EXPORT=""
    read -r ok failed < <(awk '/ \.\.\. ok$/ { ok++ } / \.\.\. FAILED$/ { failed++ } END { print ok + 0, failed + 0 }' "$saved")
    total=$((ok + failed))
    if (( CARGO_STATUS == 0 )); then
        echo "REPLAY PASSED: $stem passed at $short ($total tests); $RED_RUNS/$stem.txt is not a failing run"
        return 1
    fi
    if grep -q -- 'could not compile' "$saved"; then
        echo "REPLAY RED: $stem did not build at $short; output in $RED_RUNS/$stem.txt"
        return 0
    fi
    if (( failed > 0 )); then
        echo "REPLAY RED: $failed of $total tests failed at $short; output in $RED_RUNS/$stem.txt"
        return 0
    fi
    echo "REPLAY NOT RED: cargo test exited $CARGO_STATUS with no failed test and no build error at $short; output in $RED_RUNS/$stem.txt"
    return 1
}

# Replays every test file at HEAD that has no saved failing run, skipping the skeleton smoke tests; returns 1 when one is not red.
replay_missing() {
    local stem rc replayed=0 not_red=0
    local -a stems missing=()
    mapfile -t stems < <(head_stems)
    for stem in "${stems[@]}"; do
        if is_skeleton "$stem"; then
            echo "REPLAY-ALL: skipped crate skeleton smoke test $stem"
            continue
        fi
        find_run "$stem"
        if [[ $RUN_KIND == none ]]; then
            missing+=("$stem")
        fi
    done
    for stem in ${missing[@]+"${missing[@]}"}; do
        rc=0
        replay_one "$stem" || rc=$?
        replayed=$((replayed + 1))
        if (( rc != 0 )); then
            not_red=$((not_red + 1))
        fi
    done
    echo "REPLAY-ALL: $replayed replayed, $not_red not red"
    if (( not_red > 0 )); then
        return 1
    fi
    return 0
}

if [[ $# -eq 0 ]]; then
    report_all
elif [[ $# -eq 2 && $1 == --replay ]]; then
    [[ $2 =~ $STEM_RE ]] || fail "not a test stem: $2"
    rc=0
    replay_one "$2" || rc=$?
    exit "$rc"
elif [[ $# -eq 1 && $1 == --replay-all ]]; then
    rc=0
    replay_missing || rc=$?
    exit "$rc"
else
    echo "usage: scripts/prove-tests-first.sh [--replay STEM | --replay-all]" >&2
    exit 2
fi
