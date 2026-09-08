#!/bin/bash

# SPDX-License-Identifier: MPL-2.0

# Synchronize the FrameVM kernel fork with its recorded main baseline.
#
# The service tree is intentionally not a live link to kernel/core: FrameVM
# needs independent adaptations. This script carries changes from main with a
# file-level three-way merge, leaving FrameVM-only edits intact whenever they
# do not overlap an upstream change.

set -euo pipefail

readonly METADATA_FILE="services/aster-framevm/UPSTREAM.toml"

fail() {
    echo "error: $*" >&2
    exit 1
}

usage() {
    printf '%s\n' \
        'Usage:' \
        '  tools/sync_framevm_from_main.sh --check [UPSTREAM_REF]' \
        '  tools/sync_framevm_from_main.sh --apply [UPSTREAM_REF]' \
        '' \
        '--check verifies that the FrameVM source fork is synchronized with the' \
        'recorded upstream reference. --apply performs a three-way merge of changes' \
        'from that reference and advances UPSTREAM.toml only when every file merges' \
        'cleanly.'
}

metadata_value() {
    local key="$1"
    sed -nE "s/^${key}[[:space:]]*=[[:space:]]*\\\"([^\\\"]+)\\\"[[:space:]]*$/\\1/p" "$METADATA_FILE"
}

require_single_metadata_value() {
    local key="$1"
    local value
    value="$(metadata_value "$key")"
    [ "$(printf '%s\n' "$value" | sed '/^$/d' | wc -l)" -eq 1 ] || fail "$METADATA_FILE must contain exactly one $key value"
    printf '%s\n' "$value"
}

git_file_exists() {
    git cat-file -e "$1:$2" 2>/dev/null
}

copy_git_file_or_empty() {
    local revision="$1"
    local source_file="$2"
    local destination="$3"
    mkdir -p "$(dirname "$destination")"
    if git_file_exists "$revision" "$source_file"; then
        git show "$revision:$source_file" > "$destination"
    else
        : > "$destination"
    fi
}

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    usage >&2
    exit 2
fi

mode="$1"
case "$mode" in
    --check|--apply) ;;
    --help|-h)
        usage
        exit 0
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac

repo_root="$(git rev-parse --show-toplevel 2>/dev/null)" || fail "must run inside the Asterinas Git repository"
cd "$repo_root"

[ -f "$METADATA_FILE" ] || fail "missing $METADATA_FILE"

base_commit="$(require_single_metadata_value base_commit)"
configured_ref="$(require_single_metadata_value upstream_ref)"
source_root="$(require_single_metadata_value source_path)"
service_root="$(require_single_metadata_value service_path)"
upstream_ref="${2:-$configured_ref}"

if ! git rev-parse --verify --quiet "$base_commit^{commit}" >/dev/null; then
    fail "recorded base commit $base_commit is unavailable"
fi
if ! git rev-parse --verify --quiet "$upstream_ref^{commit}" >/dev/null; then
    fail "upstream ref $upstream_ref is unavailable"
fi
if ! git cat-file -e "$base_commit:$source_root" 2>/dev/null; then
    fail "recorded base commit has no $source_root tree"
fi
if ! git cat-file -e "$upstream_ref:$source_root" 2>/dev/null; then
    fail "upstream ref has no $source_root tree"
fi
if ! git merge-base --is-ancestor "$base_commit" "$upstream_ref"; then
    fail "recorded base $base_commit is not an ancestor of $upstream_ref"
fi

if git diff --quiet "$base_commit" "$upstream_ref" -- "$source_root"; then
    echo "FrameVM source fork is synchronized with $upstream_ref ($base_commit)."
    exit 0
fi

if [ "$mode" = "--check" ]; then
    changed_count="$(git diff --name-only "$base_commit" "$upstream_ref" -- "$source_root" | wc -l)"
    fail "FrameVM source fork is behind $upstream_ref by $changed_count file(s); run tools/sync_framevm_from_main.sh --apply $upstream_ref"
fi

if ! git diff --quiet -- "$service_root"; then
    fail "refusing to merge into a service tree with uncommitted changes; commit or stash changes under $service_root first"
fi
if [ -n "$(git ls-files --others --exclude-standard -- "$service_root")" ]; then
    fail "refusing to merge into a service tree with untracked files; add, commit, or remove files under $service_root first"
fi

temporary_root="$(mktemp -d)"
trap 'rm -rf "$temporary_root"' EXIT
declare -a merge_targets=()
declare -a delete_targets=()
declare -a conflicts=()

while IFS= read -r -d '' upstream_file; do
    relative_file="${upstream_file#"$source_root"/}"
    service_file="$service_root/$relative_file"
    file_root="$temporary_root/$relative_file"
    base_file="$file_root/base"
    current_file="$file_root/current"
    incoming_file="$file_root/incoming"
    merged_file="$file_root/merged"

    copy_git_file_or_empty "$base_commit" "$upstream_file" "$base_file"
    copy_git_file_or_empty "$upstream_ref" "$upstream_file" "$incoming_file"
    mkdir -p "$(dirname "$current_file")"
    if [ -e "$service_file" ]; then
        cp "$service_file" "$current_file"
    else
        : > "$current_file"
    fi

    if git merge-file -p "$current_file" "$base_file" "$incoming_file" > "$merged_file"; then
        if git_file_exists "$upstream_ref" "$upstream_file"; then
            merge_targets+=("$relative_file")
        else
            delete_targets+=("$relative_file")
        fi
    else
        merge_status="$?"
        if [ "$merge_status" -eq 1 ]; then
            conflicts+=("$relative_file")
        else
            fail "git merge-file failed for $relative_file"
        fi
    fi
done < <(git diff --name-only -z "$base_commit" "$upstream_ref" -- "$source_root")

if [ "${#conflicts[@]}" -ne 0 ]; then
    printf 'FrameVM upstream merge has conflicts in:\n' >&2
    printf '  %s\n' "${conflicts[@]}" >&2
    exit 1
fi

for relative_file in "${merge_targets[@]}"; do
    service_file="$service_root/$relative_file"
    merged_file="$temporary_root/$relative_file/merged"
    mkdir -p "$(dirname "$service_file")"
    chmod 644 "$merged_file"
    mv "$merged_file" "$service_file"
done
for relative_file in "${delete_targets[@]}"; do
    rm -f "$service_root/$relative_file"
done

next_base="$(git rev-parse "$upstream_ref")"
updated_metadata="$temporary_root/UPSTREAM.toml"
sed "s/^base_commit[[:space:]]*=.*/base_commit = \\\"$next_base\\\"/" "$METADATA_FILE" > "$updated_metadata"
mv "$updated_metadata" "$METADATA_FILE"

echo "FrameVM source fork synchronized with $upstream_ref."
