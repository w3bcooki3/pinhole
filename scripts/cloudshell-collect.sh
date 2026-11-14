#!/usr/bin/env bash
#
# Pinhole snapshot collector for AWS CloudShell (or any shell with the AWS
# CLI v2 and jq).
#
# It only calls read-only describe/get/search APIs and writes one JSON file.
# Nothing in the account is created or changed. The minimal IAM policy it
# needs is in docs/iam-policy.json.
#
# Usage:
#   ./cloudshell-collect.sh [region] [output-file]
#
#   region       defaults to $AWS_REGION, then the CLI's configured region
#   output-file  defaults to pinhole-snapshot-<account>-<region>.json
#
# Then download the file (CloudShell: Actions > Download file) and either
# drop it on the Pinhole web page, which analyses it inside your browser,
# or run `pinhole exposure <file>` on your own machine. The file contains
# your network configuration; treat it as sensitive and do not commit it.

set -euo pipefail
# The snapshot describes your network; keep it readable only by you.
umask 077

command -v aws >/dev/null || { echo "error: the AWS CLI is required" >&2; exit 1; }
command -v jq >/dev/null || { echo "error: jq is required" >&2; exit 1; }

REGION="${1:-${AWS_REGION:-$(aws configure get region 2>/dev/null || true)}}"
if [[ -z "${REGION}" ]]; then
  echo "error: no region given and none configured; pass one, e.g. $0 us-east-1" >&2
  exit 1
fi
if [[ ! "${REGION}" =~ ^[a-z]{2}(-[a-z]+)+-[0-9]+$ ]]; then
  echo "error: \"${REGION}\" is not a region name, e.g. us-east-1" >&2
  exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
ERRORS="${WORK}/errors.jsonl"
: > "${ERRORS}"

# call <file> <aws args...>
# Runs one read-only AWS CLI command (the CLI follows pagination itself).
# On failure, records the error and writes "{}" so the rest still works.
call() {
  local out="$1"; shift
  local api="$1:$2"
  echo "  ${api}" >&2
  if ! aws "$@" --region "${REGION}" --output json > "${out}" 2> "${out}.err"; then
    jq -cn --arg api "${api}" --arg msg "$(tr '\n' ' ' < "${out}.err")" '{api: $api, message: $msg}' >> "${ERRORS}"
    echo '{}' > "${out}"
  fi
}

echo "Collecting network configuration in ${REGION} (read-only)..." >&2

ACCOUNT="$(aws sts get-caller-identity --query Account --output text --region "${REGION}")"

call "${WORK}/vpcs.json"      ec2 describe-vpcs
call "${WORK}/subnets.json"   ec2 describe-subnets
call "${WORK}/rtbs.json"      ec2 describe-route-tables
call "${WORK}/igws.json"      ec2 describe-internet-gateways
call "${WORK}/eigws.json"     ec2 describe-egress-only-internet-gateways
call "${WORK}/nats.json"      ec2 describe-nat-gateways
call "${WORK}/pcx.json"       ec2 describe-vpc-peering-connections
call "${WORK}/tgws.json"      ec2 describe-transit-gateways
call "${WORK}/tgwatt.json"    ec2 describe-transit-gateway-attachments
call "${WORK}/tgwvpcatt.json" ec2 describe-transit-gateway-vpc-attachments
call "${WORK}/tgwrtbs.json"   ec2 describe-transit-gateway-route-tables
call "${WORK}/nacls.json"     ec2 describe-network-acls
call "${WORK}/sgs.json"       ec2 describe-security-groups
call "${WORK}/sgrules.json"   ec2 describe-security-group-rules
call "${WORK}/pls.json"       ec2 describe-managed-prefix-lists
call "${WORK}/enis.json"      ec2 describe-network-interfaces
call "${WORK}/instances.json" ec2 describe-instances
call "${WORK}/vpces.json"     ec2 describe-vpc-endpoints

# Transit gateway routes, one search per route table.
echo '{}' > "${WORK}/tgwroutes.json"
for rtb in $(jq -r '.TransitGatewayRouteTables[]?.TransitGatewayRouteTableId' "${WORK}/tgwrtbs.json"); do
  call "${WORK}/tgwr-${rtb}.json" ec2 search-transit-gateway-routes \
    --transit-gateway-route-table-id "${rtb}" --filters Name=state,Values=active,blackhole --max-results 1000
  # Not paginated. A partial route table could make a path look blocked, so a
  # truncated one is left out and paths through it are reported as unknown.
  if jq -e '.AdditionalRoutesAvailable == true' "${WORK}/tgwr-${rtb}.json" >/dev/null; then
    jq -cn --arg rtb "${rtb}" '{api: "ec2:SearchTransitGatewayRoutes", message: ($rtb + " has more than 1000 routes; its routes were not used.")}' >> "${ERRORS}"
  elif jq -e 'has("Routes")' "${WORK}/tgwr-${rtb}.json" >/dev/null; then
    jq --arg id "${rtb}" --slurpfile r "${WORK}/tgwr-${rtb}.json" '. + {($id): $r[0].Routes}' \
      "${WORK}/tgwroutes.json" > "${WORK}/tmp.json" && mv "${WORK}/tmp.json" "${WORK}/tgwroutes.json"
  fi
done

# Prefix list entries, only for lists referenced by SG rules or routes.
echo '{}' > "${WORK}/plentries.json"
for pl in $(jq -r -s '[.[0].SecurityGroupRules[]?.PrefixListId, .[1].RouteTables[]?.Routes[]?.DestinationPrefixListId] | map(select(. != null)) | unique | .[]' \
              "${WORK}/sgrules.json" "${WORK}/rtbs.json"); do
  call "${WORK}/ple-${pl}.json" ec2 get-managed-prefix-list-entries --prefix-list-id "${pl}"
  if jq -e 'has("Entries")' "${WORK}/ple-${pl}.json" >/dev/null; then
    jq --arg id "${pl}" --slurpfile r "${WORK}/ple-${pl}.json" '. + {($id): $r[0].Entries}' \
      "${WORK}/plentries.json" > "${WORK}/tmp.json" && mv "${WORK}/tmp.json" "${WORK}/plentries.json"
  fi
done

# Elastic Load Balancing v2.
call "${WORK}/lbs.json" elbv2 describe-load-balancers
echo '[]' > "${WORK}/listeners.json"
echo '[]' > "${WORK}/rules.json"
for lb in $(jq -r '.LoadBalancers[]?.LoadBalancerArn' "${WORK}/lbs.json"); do
  f="${WORK}/l-$(echo "${lb}" | md5sum | cut -c1-12).json"
  call "${f}" elbv2 describe-listeners --load-balancer-arn "${lb}"
  jq -s '.[0] + (.[1].Listeners // [])' "${WORK}/listeners.json" "${f}" > "${WORK}/tmp.json" && mv "${WORK}/tmp.json" "${WORK}/listeners.json"
  if [[ "$(jq -r --arg a "${lb}" '.LoadBalancers[] | select(.LoadBalancerArn == $a) | .Type' "${WORK}/lbs.json")" == "application" ]]; then
    for l in $(jq -r '.Listeners[]?.ListenerArn' "${f}"); do
      rf="${WORK}/r-$(echo "${l}" | md5sum | cut -c1-12).json"
      call "${rf}" elbv2 describe-rules --listener-arn "${l}"
      jq -s --arg l "${l}" '.[0] + ((.[1].Rules // []) | map(. + {ListenerArn: $l}))' "${WORK}/rules.json" "${rf}" > "${WORK}/tmp.json" && mv "${WORK}/tmp.json" "${WORK}/rules.json"
    done
  fi
done
call "${WORK}/tgs.json" elbv2 describe-target-groups
echo '{}' > "${WORK}/health.json"
echo '{}' > "${WORK}/tgattrs.json"
for tg in $(jq -r '.TargetGroups[]?.TargetGroupArn' "${WORK}/tgs.json"); do
  h="${WORK}/h-$(echo "${tg}" | md5sum | cut -c1-12).json"
  call "${h}" elbv2 describe-target-health --target-group-arn "${tg}"
  if jq -e 'has("TargetHealthDescriptions")' "${h}" >/dev/null; then
    jq --arg id "${tg}" --slurpfile r "${h}" '. + {($id): $r[0].TargetHealthDescriptions}' "${WORK}/health.json" > "${WORK}/tmp.json" && mv "${WORK}/tmp.json" "${WORK}/health.json"
  fi
  a="${WORK}/a-$(echo "${tg}" | md5sum | cut -c1-12).json"
  call "${a}" elbv2 describe-target-group-attributes --target-group-arn "${tg}"
  if jq -e 'has("Attributes")' "${a}" >/dev/null; then
    jq --arg id "${tg}" --slurpfile r "${a}" '. + {($id): $r[0].Attributes}' "${WORK}/tgattrs.json" > "${WORK}/tmp.json" && mv "${WORK}/tmp.json" "${WORK}/tgattrs.json"
  fi
done

OUT="${2:-pinhole-snapshot-${ACCOUNT}-${REGION}.json}"

# Assemble. Keys mirror the API response fields; see packages/engine/src/snapshot.ts.
jq -n \
  --arg account "${ACCOUNT}" --arg region "${REGION}" --arg now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --slurpfile vpcs "${WORK}/vpcs.json" --slurpfile subnets "${WORK}/subnets.json" \
  --slurpfile rtbs "${WORK}/rtbs.json" --slurpfile igws "${WORK}/igws.json" \
  --slurpfile eigws "${WORK}/eigws.json" --slurpfile nats "${WORK}/nats.json" \
  --slurpfile pcx "${WORK}/pcx.json" --slurpfile tgws "${WORK}/tgws.json" \
  --slurpfile tgwatt "${WORK}/tgwatt.json" --slurpfile tgwvpcatt "${WORK}/tgwvpcatt.json" \
  --slurpfile tgwrtbs "${WORK}/tgwrtbs.json" --slurpfile tgwroutes "${WORK}/tgwroutes.json" \
  --slurpfile nacls "${WORK}/nacls.json" --slurpfile sgs "${WORK}/sgs.json" \
  --slurpfile sgrules "${WORK}/sgrules.json" --slurpfile pls "${WORK}/pls.json" \
  --slurpfile plentries "${WORK}/plentries.json" --slurpfile enis "${WORK}/enis.json" \
  --slurpfile instances "${WORK}/instances.json" --slurpfile vpces "${WORK}/vpces.json" \
  --slurpfile lbs "${WORK}/lbs.json" --slurpfile listeners "${WORK}/listeners.json" \
  --slurpfile rules "${WORK}/rules.json" --slurpfile tgs "${WORK}/tgs.json" \
  --slurpfile health "${WORK}/health.json" --slurpfile tgattrs "${WORK}/tgattrs.json" \
  --slurpfile errors <(jq -s '.' "${ERRORS}") \
  '{
    schemaVersion: 1,
    source: "aws-cli",
    tool: {name: "pinhole-cloudshell-collect"},
    collectedAt: $now,
    accountId: $account,
    region: $region,
    ec2: {
      Vpcs: ($vpcs[0].Vpcs // []),
      Subnets: ($subnets[0].Subnets // []),
      RouteTables: ($rtbs[0].RouteTables // []),
      InternetGateways: ($igws[0].InternetGateways // []),
      EgressOnlyInternetGateways: ($eigws[0].EgressOnlyInternetGateways // []),
      NatGateways: ($nats[0].NatGateways // []),
      VpcPeeringConnections: ($pcx[0].VpcPeeringConnections // []),
      TransitGateways: ($tgws[0].TransitGateways // []),
      TransitGatewayAttachments: ($tgwatt[0].TransitGatewayAttachments // []),
      TransitGatewayVpcAttachments: ($tgwvpcatt[0].TransitGatewayVpcAttachments // []),
      TransitGatewayRouteTables: ($tgwrtbs[0].TransitGatewayRouteTables // []),
      TransitGatewayRoutes: $tgwroutes[0],
      NetworkAcls: ($nacls[0].NetworkAcls // []),
      SecurityGroups: ($sgs[0].SecurityGroups // []),
      SecurityGroupRules: ($sgrules[0].SecurityGroupRules // []),
      ManagedPrefixLists: ($pls[0].PrefixLists // []),
      PrefixListEntries: $plentries[0],
      NetworkInterfaces: ($enis[0].NetworkInterfaces // []),
      Instances: [($instances[0].Reservations // [])[] | .Instances[]?],
      VpcEndpoints: ($vpces[0].VpcEndpoints // [])
    },
    elbv2: {
      LoadBalancers: ($lbs[0].LoadBalancers // []),
      Listeners: $listeners[0],
      Rules: $rules[0],
      TargetGroups: ($tgs[0].TargetGroups // []),
      TargetHealth: $health[0],
      TargetGroupAttributes: $tgattrs[0]
    }
  } + (if ($errors[0] | length) > 0 then {errors: $errors[0]} else {} end)' > "${OUT}"

n_err="$(wc -l < "${ERRORS}" | tr -d ' ')"
FULL="$(cd "$(dirname "${OUT}")" && pwd)/$(basename "${OUT}")"
echo "" >&2
echo "Done. Snapshot written to:" >&2
echo "  ${FULL}" >&2
echo "" >&2
echo "Next: in CloudShell choose Actions > Download file, paste the path above," >&2
echo "then open Pinhole in your browser and load the downloaded file." >&2
if [[ "${n_err}" != "0" ]]; then
  echo "warning: ${n_err} API call(s) failed (see the \"errors\" field); results that depend on them will be marked incomplete." >&2
fi
