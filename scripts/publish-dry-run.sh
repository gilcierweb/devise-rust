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
#
# Classification (WR-01 fix): a registry-resolution failure counts as a
# DEFERRAL only when the missing crate named in cargo's error is an
# earlier-in-ORDER, publishable member. Any other outcome (a
# publish=false harness, the member itself, a later-in-DAG sibling, or
# an unrecognized error shape) aborts the gate with the full cargo
# output, so a permanent publish blocker can never be reported as a
# deferred-temporary one. `--self-test` pins those verdicts on
# synthetic outputs (a pure function test: no network access, no cargo
# invocation).
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

# Extract the crate name cargo names in a registry-resolution failure.
# Two real cargo error shapes carry the name in backticks:
#   no matching package named `NAME` found
#   failed to select a version for the package `NAME`
# Prints the name, or nothing when the output matches neither shape.
extract_missing_crate_name() {
  local output="$1"
  local re_no_match='no matching package named `([^`]+)`'
  local re_select='failed to select a version for the package `([^`]+)`'
  if [[ "$output" =~ $re_no_match ]]; then
    printf '%s' "${BASH_REMATCH[1]}"
  elif [[ "$output" =~ $re_select ]]; then
    printf '%s' "${BASH_REMATCH[1]}"
  fi
}

# Verdict for a failed dry run of MEMBER: defer (exit 0) only when the
# output carries cargo's failed-to-prepare marker, the missing crate
# named in the error sits in ORDER strictly before MEMBER, it is not
# MEMBER itself, and it is publishable (directory present, manifest
# does not set publish = false, same grep as the skip branch). Every
# other outcome returns 1 so the caller aborts with the full output.
is_registry_blocked_resolution() {
  local output="$1"
  local member="$2"
  [[ "$output" == *"failed to prepare local package for uploading"* ]] || return 1
  local missing
  missing=$(extract_missing_crate_name "$output")
  [ -n "$missing" ] || return 1
  [ "$missing" != "$member" ] || return 1
  local member_pos=-1
  local missing_pos=-1
  local idx
  for idx in "${!ORDER[@]}"; do
    if [ "${ORDER[$idx]}" = "$member" ]; then member_pos=$idx; fi
    if [ "${ORDER[$idx]}" = "$missing" ]; then missing_pos=$idx; fi
  done
  [ "$member_pos" -ge 0 ] || return 1
  [ "$missing_pos" -ge 0 ] || return 1
  [ "$missing_pos" -lt "$member_pos" ] || return 1
  local dir="crates/$missing"
  [ -d "$dir" ] || return 1
  ! grep -q '^publish = false' "$dir/Cargo.toml" || return 1
  return 0
}

# --self-test: pin the classifier's defer and abort verdicts on
# synthetic outputs (the WR-01 regression guard). Runs before the DAG
# loop; performs no network access and invokes no cargo command.
if [ "${1:-}" = "--self-test" ]; then
  self_test_failures=0
  run_self_test_case() {
    local case_id="$1"
    local member="$2"
    local expected="$3"
    local output="$4"
    local actual
    local missing
    if is_registry_blocked_resolution "$output" "$member"; then
      actual="defer"
    else
      actual="abort"
    fi
    missing=$(extract_missing_crate_name "$output")
    if [ -z "$missing" ]; then
      missing="(none)"
    fi
    echo "self-test $case_id: member=$member missing=$missing expected=$expected actual=$actual"
    if [ "$actual" != "$expected" ]; then
      self_test_failures=$((self_test_failures + 1))
    fi
  }

  # Case a (prescribed): the core is missing while packaging the diesel
  # backend; the core is an earlier-in-ORDER publishable member, so the
  # verdict is defer. Uses the exact error shape the real tree emits.
  out_a='error: failed to prepare local package for uploading
Caused by:
  no matching package named `devise-rust` found
  location searched: crates.io index
required by package `devise-rust-diesel v0.1.0`'
  run_self_test_case a devise-rust-diesel defer "$out_a"

  # Case b (prescribed): the publish=false harness is missing; it is not
  # in ORDER (and is not publishable), so this is the permanent CR-01
  # blocker class and must abort, never defer.
  out_b='error: failed to prepare local package for uploading
Caused by:
  no matching package named `devise-rust-adapter-tests` found
  location searched: crates.io index
required by package `devise-rust-diesel v0.1.0`'
  run_self_test_case b devise-rust-diesel abort "$out_b"

  # Case c (prescribed): the missing package is the member itself (the
  # version-carrying self-dev-dependency, CR-02); must abort.
  out_c='error: failed to prepare local package for uploading
Caused by:
  no matching package named `devise-rust-axum` found
  location searched: crates.io index
required by package `devise-rust-axum v0.1.0`'
  run_self_test_case c devise-rust-axum abort "$out_c"

  # Case d (prescribed): the axum crate is missing while packaging the
  # actix crate; axum sits later in ORDER, so at a real publish session
  # this is a permanent blocker and must abort.
  out_d='error: failed to prepare local package for uploading
Caused by:
  no matching package named `devise-rust-axum` found
  location searched: crates.io index
required by package `devise-rust-actix v0.1.0`'
  run_self_test_case d devise-rust-actix abort "$out_d"

  # Case e (prescribed): a generic cargo metadata error with no
  # resolution shape; the marker is present but no crate name can be
  # parsed, so the gate must fail closed and abort.
  out_e='error: failed to prepare local package for uploading
Caused by:
  `package.description` is required for publishing'
  run_self_test_case e devise-rust-diesel abort "$out_e"

  # Case f (bonus): the second real cargo error shape names an
  # earlier-in-ORDER publishable member (migrations, the first DAG
  # leaf); the verdict is defer, pinning the shape-2 parser and the
  # strictly-before check for a non-core member.
  out_f='error: failed to prepare local package for uploading
Caused by:
  failed to select a version for the package `devise-rust-migrations`
    ... required by package `devise-rust-diesel v0.1.0`'
  run_self_test_case f devise-rust-diesel defer "$out_f"

  if [ "$self_test_failures" -eq 0 ]; then
    echo "self-test: 6/6 classifier verdicts match (5 prescribed cases + 1 shape-2 defer pin)"
    exit 0
  fi
  echo "self-test: $self_test_failures verdict mismatch(es)" >&2
  exit 1
fi

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
  elif is_registry_blocked_resolution "$output" "$crate"; then
    missing=$(extract_missing_crate_name "$output")
    echo "deferred full dry-run: $crate (missing registry package: $missing; an earlier-in-DAG member not yet uploaded; the full pipeline completes at real publish time once $missing uploads)"
    echo "packaging proof for $crate (cargo package --list):"
    cargo package -p "$crate" --list | sed 's/^/  /'
  else
    printf '%s\n' "$output" >&2
    exit 1
  fi
done

echo "DAG dry run complete: every publishable member packaged clean."
