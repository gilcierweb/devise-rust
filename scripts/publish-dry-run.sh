#!/usr/bin/env bash
# scripts/publish-dry-run.sh - dry-run every publishable workspace member
# in dependency DAG order (D-15). Never uploads anything: cargo aborts
# every run before the upload step. Run from anywhere; the script cds to
# the workspace root (its parent directory).
#
# Cargo publish mechanics note: `cargo publish --dry-run` resolves the
# packaged manifest against the real crates.io registry, so a member
# whose intra-workspace dependencies have not been uploaded yet cannot
# complete the full pipeline (the registry has no devise-rust 0.1.0 to
# resolve the rewritten dependency against). For those members this
# script proves the packaging layer with `cargo package --list` (the
# T-10-03 audit surface: file inventory, in-package README and
# LICENSE-MIT inclusion, no stray fixtures) and records an explicit
# deferral line. Once earlier DAG members are uploaded in a real
# publish session, the same dry runs succeed with no change here.
set -euo pipefail

cd "$(dirname "$0")/.."

# Leaf crates first, then core, then backends, then integrations:
# migrations and the core crate have no intra-workspace dependencies;
# backends depend on core; integrations depend on core (plus backends
# through dev-dependencies).
ORDER=(
  devise-rust-migrations
  devise-rust
  devise-rust-diesel
  devise-rust-sqlx
  devise-rust-sea-orm
  devise-rust-actix
  devise-rust-axum
)

# Failure markers cargo prints when the registry cannot resolve an
# intra-workspace dependency of the member being packaged (the sibling
# crate exists only as a path dependency until it is actually uploaded).
RESOLUTION_FAILURES=(
  'no matching package named `devise-rust'
  'failed to select a version'
  'no matching version'
  'location searched: crates.io index'
)

is_registry_blocked_resolution() {
  local output="$1"
  [[ "$output" == *"failed to prepare local package for uploading"* ]] || return 1
  local marker
  for marker in "${RESOLUTION_FAILURES[@]}"; do
    if [[ "$output" == *"$marker"* ]]; then
      return 0
    fi
  done
  return 1
}

for crate in "${ORDER[@]}"; do
  dir="crates/$crate"
  if [ ! -d "$dir" ]; then
    echo "skip: $crate (directory $dir absent at execution time)"
    continue
  fi
  if grep -q '^publish = false' "$dir/Cargo.toml"; then
    echo "skip: $crate (manifest sets publish = false; test-only harness)"
    continue
  fi

  echo "--- dry-run: $crate ---"
  if output=$(cargo publish --dry-run -p "$crate" 2>&1); then
    printf '%s\n' "$output"
  elif is_registry_blocked_resolution "$output"; then
    echo "deferred full dry-run: $crate (an intra-workspace dependency is not yet on crates.io; the full pipeline completes at real publish time once earlier DAG members upload)"
    echo "packaging proof for $crate (cargo package --list):"
    cargo package -p "$crate" --list | sed 's/^/  /'
  else
    printf '%s\n' "$output" >&2
    exit 1
  fi
done

echo "DAG dry run complete: every publishable member packaged clean."
