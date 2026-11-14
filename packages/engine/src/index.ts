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
export type { Chokepoint, FixCandidate, FixPlan, PlanStep } from './fixes.js';
export { analyzeHygiene } from './hygiene.js';
export type { HygieneCode, HygieneFinding } from './hygiene.js';
export { detectOutOfScope } from './scope.js';
export { assessPorts, categorize, compareSeverity, isPivotService, serviceName, SEVERITY_ORDER } from './risk.js';
export type { Severity, RiskAssessment, ServiceCategory } from './risk.js';
export { reachServices, serviceLabel, isLateralTarget } from './reach.js';
export type { PairReach, ServiceReach, ReachOptions } from './reach.js';
export { analyzeBlastRadius, findingKey } from './blast.js';
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
