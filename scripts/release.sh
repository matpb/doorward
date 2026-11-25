#!/usr/bin/env bash
# Release a version: bump it everywhere it is stated, commit, tag, and update the project page.
# Usage: scripts/release.sh X.Y.Z [--push]
set -euo pipefail

new="${1:-}"
push="${2:-}"
[[ "$new" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "usage: scripts/release.sh X.Y.Z [--push]" >&2; exit 2; }
[[ -z "$push" || "$push" == "--push" ]] || { echo "unknown option: $push" >&2; exit 2; }

cd "$(git rev-parse --show-toplevel)"
[[ "$(git branch --show-current)" == "main" ]] || { echo "release from main" >&2; exit 1; }
[[ -z "$(git status --porcelain)" ]] || { echo "the working tree is not clean" >&2; exit 1; }
git rev-parse -q --verify "refs/tags/v$new" >/dev/null && { echo "tag v$new exists" >&2; exit 1; }

old="$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n 1)"
[[ -n "$old" && "$old" != "$new" ]] || { echo "Cargo.toml already says $new" >&2; exit 1; }

sed -i "0,/^version = \"$old\"$/s//version = \"$new\"/" Cargo.toml
sed -i "/^name = \"doorward\"$/{n;s/^version = \"$old\"$/version = \"$new\"/}" Cargo.lock
sed -i "s/^Status: $old\.$/Status: $new./" README.md
for file in Cargo.toml Cargo.lock README.md; do
    git diff --quiet -- "$file" && { echo "$file did not change: fix the release script" >&2; exit 1; }
done

# The pre-commit hook runs the whole check.
git commit -q -am "Release $new"
git tag -a "v$new" -m "Doorward $new"

# The project page lives on the gh-pages branch and states the version in its text.
page="$(mktemp -d)"
trap 'git worktree remove --force "$page" 2>/dev/null || true' EXIT
git fetch -q origin gh-pages
git worktree add -q --detach "$page" origin/gh-pages
sed -i -E "s/Version [0-9]+\.[0-9]+\.[0-9]+/Version $new/g" "$page/index.html"
grep -q "Version $new" "$page/index.html" || { echo "the page states no version: fix the release script" >&2; exit 1; }
if ! git -C "$page" diff --quiet; then
    git -C "$page" commit -q --no-verify -am "Version $new"
fi
git branch -q -f gh-pages "$(git -C "$page" rev-parse HEAD)"

if [[ "$push" == "--push" ]]; then
    git push origin main "v$new" gh-pages
    echo "released $new: main, v$new and the project page are pushed"
else
    echo "prepared $new locally: push with 'git push origin main v$new gh-pages'"
fi
