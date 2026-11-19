/**
 * @pinhole/engine: offline evaluation of AWS VPC reachability.
 *
 * This package has no I/O and no AWS SDK dependency, so it runs unchanged in
 * Node (CLI, GitHub Action) and in a browser (static web page).
 */
export { normalize } from './normalize.js';
export { evaluatePath, evaluateClientPreservedTarget, CLIENT_PROFILES, ELB_PROFILES } from './path.js';
export type { Endpoint, PathQuery, PathResult, EphemeralProfile, ReturnCoverage, ReturnProfileResult, EvaluateOptions } from './path.js';
export { analyzeExposure } from './exposure.js';
export type { ExposureFinding, ExposureReport, ExposureOptions, LbTargetResult } from './exposure.js';
export { applyChanges, cliFor, describeChange, diffExposure, ruleText, ChangeError, assertChanges } from './whatif.js';
export type { Change, DiffStatus, ExposureDelta, ExposureDiff } from './whatif.js';
export { findChokepoints, findFixes, planFixes } from './fixes.js';
export type { PlanOptions } from './fixes.js';
export { describeBreak, internalBreaks, internalFlows, isWanted, summarizeBreaks, touchedInterfaces } from './internal.js';
export type { Breakage, Evidence, InternalFlow } from './internal.js';
export { changeScope, crossChains, joinSnapshots } from './join.js';
export type { CrossChain, CrossReport, JoinedEstate, JoinInput, JoinLink, JoinResult } from './join.js';
export type { Chokepoint, FixCandidate, FixPlan, PlanStep } from './fixes.js';
export { analyzeHygiene } from './hygiene.js';
export type { HygieneCode, HygieneFinding } from './hygiene.js';
export { detectOutOfScope } from './scope.js';
export { assessPorts, categorize, compareSeverity, isPivotService, serviceName, SEVERITY_ORDER } from './risk.js';
export type { Severity, RiskAssessment, ServiceCategory } from './risk.js';
export { reachServices, serviceLabel, isLateralTarget } from './reach.js';
export type { PairReach, ServiceReach, ReachOptions } from './reach.js';
export { analyzeBlastRadius, analyzeOnPremBlast, blastGroupRep, findingKey, reachBetween } from './blast.js';
export type { AttackChain, BlastEntry, BlastFootprint, BlastReport, BlastOptions, ChainStep, LateralEdge } from './blast.js';
export type { Hop, Stage } from './walk.js';
export { SNAPSHOT_SCHEMA_VERSION, SnapshotError, assertSnapshot } from './snapshot.js';
export type { Snapshot } from './snapshot.js';
export { DOCS } from './docs.js';
export { parseIpv4, formatIpv4, parseCidr, RangeSet, INTERNET } from './ipv4.js';
export type * from './types.js';
export { diffSnapshots, DriftError } from './drift.js';
export type { ConfigChange, ConfigKind, SnapshotDiff } from './drift.js';
export { mapTerraformPlan, PlanError } from './terraform.js';
export type { PlanMapping, PlanResourceResult } from './terraform.js';
export { analyzeEgress } from './egress.js';
export { analyzeOnPrem } from './hybrid.js';
export { firewallHygiene } from './fwhygiene.js';
export { repairPath } from './repair.js';
export type { RepairResult, RepairStep } from './repair.js';
export { analyzePrivateLink, fullAccessPolicy, privateLinkWorst } from './privatelink.js';
export type { PrivateLinkReport, PrivateLinkService, PrivateLinkEndpoint, PrivateLinkListener } from './privatelink.js';
export type { OnPremFinding, OnPremReport } from './hybrid.js';
export { onPremLinks, onPremNetworks, describeLink } from './onprem.js';
export type { OnPremLink, OnPremNetwork } from './onprem.js';
export type { EgressFinding, EgressReport } from './egress.js';
export { analyzeCleanup, cleanupFindings, QUOTAS, sameRules } from './cleanup.js';
export type { CleanupReport, Compaction, QuotaWarning, RedundantRule, ShadowedEntry } from './cleanup.js';
export { findCrownJewels, findMinCut } from './cut.js';
export type { CrownJewel, CutEdge, MinCut } from './cut.js';
export { checkPolicy, diffPolicy, parsePolicy, PolicyError } from './policy.js';
export type { PolicyFile, PolicyReport, PolicyResult, PolicyRule, Selector, Target, Violation } from './policy.js';
export { analyzeSavings, PRICES } from './savings.js';
export type { SavingsCode, SavingsFinding, SavingsReport } from './savings.js';
export { decodeBytes, ingest, parseJsonText, scrubSecrets, sniffBinary } from './ingest.js';
export type { IngestInput, IngestResult, IngestedSnapshot } from './ingest.js';
