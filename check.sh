#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

# Test files written ahead of their code are listed here until that code exists.
RED_LIST=tests/expected-red.txt

cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings

red=()
if [[ -f "$RED_LIST" ]]; then
    while IFS= read -r name; do
        [[ -z "$name" || "$name" == \#* ]] && continue
        [[ -f "tests/$name.rs" ]] || { echo "check: $RED_LIST names a missing file: $name" >&2; exit 1; }
        red+=("$name")
    done < "$RED_LIST"
fi

green=()
for file in tests/*.rs; do
    name=$(basename "$file" .rs)
    skip=0
    for r in "${red[@]:-}"; do
        [[ "$r" == "$name" ]] && skip=1
    done
    [[ $skip -eq 0 ]] && green+=(--test "$name")
done

cargo test --lib --bins
cargo test "${green[@]}"

# A listed file must still compile and still fail; one that passes has to leave the list.
for name in "${red[@]:-}"; do
    [[ -z "$name" ]] && continue
    cargo test --test "$name" --no-run
    if cargo test --test "$name" >/dev/null 2>&1; then
        echo "check: tests/$name.rs passes now: remove it from $RED_LIST" >&2
        exit 1
    fi
done
echo "check: ${#red[@]} test file(s) still expected to fail"

cargo audit
cargo deny check
./scripts/hygiene.sh
echo "CHECK PASS"
