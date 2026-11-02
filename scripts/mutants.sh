#!/usr/bin/env bash
# Mutation testing of one area of the security-relevant code, used by the
# release gate and runnable locally the same way.
#
#   scripts/mutants.sh AREA SHARD SHARDS [DIFF]
#
# AREA picks the files to mutate and the tests that can catch their mutants.
# Running only those tests (not the whole suite) is what keeps a mutant at
# seconds instead of a minute. A filter that leaves out a test able to catch a
# mutant makes that mutant show up as missed, so a too-narrow filter fails the
# gate; it can never let a real gap pass.
#
# DIFF, when given, limits the run to mutants in code that diff touches.
set -euo pipefail

area=${1:?area}
shard=${2:?shard}
shards=${3:?shards}
diff=${4:-}

case "$area" in
  passkey)
    files=(-f 'src/passkey/**')
    tests='test(/^(passkey|autofill|cxf)::/) | test(/^business::(fields|export|items|search)::/)'
    tests+=' | binary(passkey_autofill_tests) | binary(cxf_tests) | binary(compat_tests)'
    tests+=' | binary(redaction_tests) | binary(wipe_on_drop)'
    ;;
  cxf)
    files=(-f 'src/cxf/**')
    tests='test(/^cxf::/) | binary(cxf_tests) | binary(cxf_memory)'
    ;;
  autofill)
    files=(-f src/autofill/wallet.rs -f src/autofill/index.rs -f src/autofill/journal.rs)
    tests='test(/^(autofill|passkey)::/) | binary(passkey_autofill_tests) | binary(cxf_tests)'
    tests+=' | binary(compat_tests) | binary(redaction_tests) | binary(wipe_on_drop)'
    ;;
  restore)
    files=(-f src/backup/restore.rs)
    tests='test(/^(backup|business::wallet)::/) | binary(backup_tests) | binary(compat_tests)'
    tests+=' | binary(integration_tests) | binary(migration_tests) | binary(passkey_autofill_tests)'
    ;;
  *)
    echo "unknown area: $area" >&2
    exit 2
    ;;
esac

scope=()
if [[ -n "$diff" ]]; then
  scope=(--in-diff "$diff")
fi

# A mutant can turn a loop into an endless allocation that starves the runner
# long before the timeout. Capping every process at 6 GiB, two tests at a
# time, makes such a mutant fail its test (caught) instead.
ulimit -v 6291456
export NEXTEST_TEST_THREADS=2
exec cargo mutants --test-tool=nextest --profile=mutants --timeout 300 \
  --shard "$shard/$shards" "${files[@]}" "${scope[@]}" \
  --cargo-test-arg=-E --cargo-test-arg="$tests"
