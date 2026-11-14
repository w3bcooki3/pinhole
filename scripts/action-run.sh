#!/usr/bin/env bash
# Runs Pinhole for the GitHub Action (action.yml). Inputs arrive as
# environment variables: CMD, SNAPSHOT, BASELINE, PLAN, FAIL_ON, SARIF,
# SUMMARY, and PINHOLE (path to the CLI). Exit code 2 means the --fail-on
# threshold was reached.
set -euo pipefail

fail() { echo "::error::$*" >&2; exit 1; }
[[ -n "${PINHOLE:-}" && -f "${PINHOLE}" ]] || fail "Pinhole is not built."
[[ -n "${SNAPSHOT:-}" ]] || fail "The snapshot input is required."
[[ -f "${SNAPSHOT}" ]] || fail "Snapshot file not found: ${SNAPSHOT}"

fail_args=()
if [[ -n "${FAIL_ON:-}" ]]; then
  case "${FAIL_ON}" in
    critical|high|medium|low|info) fail_args=(--fail-on "${FAIL_ON}") ;;
    *) fail "fail-on must be one of critical, high, medium, low, info, or empty." ;;
  esac
fi

case "${CMD:-exposure}" in
  exposure) args=(exposure "${SNAPSHOT}") ;;
  diff)
    [[ -n "${BASELINE:-}" && -f "${BASELINE}" ]] || fail "diff needs the baseline input: the older snapshot."
    args=(diff "${BASELINE}" "${SNAPSHOT}") ;;
  plan)
    [[ -n "${PLAN:-}" && -f "${PLAN}" ]] || fail "plan needs the plan input: the output of terraform show -json PLANFILE."
    args=(plan "${SNAPSHOT}" "${PLAN}") ;;
  *) fail "command must be exposure, diff or plan." ;;
esac

if [[ "${CMD:-exposure}" == "exposure" && -n "${SARIF:-}" ]]; then
  node "${PINHOLE}" exposure "${SNAPSHOT}" --format sarif > "${SARIF}"
  echo "SARIF written to ${SARIF}"
fi

if [[ "${SUMMARY:-true}" == "true" && -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  node "${PINHOLE}" "${args[@]}" --format markdown >> "${GITHUB_STEP_SUMMARY}" || true
fi

# The text report goes to the log; its exit code decides the step.
set +e
node "${PINHOLE}" "${args[@]}" "${fail_args[@]}"
code=$?
set -e
if [[ ${code} -eq 2 ]]; then
  echo "::error::Pinhole found exposure at or above ${FAIL_ON}. See the log or the job summary."
fi
exit ${code}
