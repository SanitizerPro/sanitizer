/**
 * SanitizerPro
 * Local Policy Engine
 *
 * Responsibilities:
 * - Convert scanner findings into ALLOW / WARN / MASK / BLOCK.
 * - Apply category and severity policies.
 * - Apply confidence thresholds.
 * - Apply aggregate risk thresholds.
 * - Support platform-specific policy overrides.
 * - Support source-specific policy overrides.
 * - Never access Chrome APIs.
 * - Never access the network.
 * - Never persist raw sensitive data.
 *
 * IMPORTANT:
 * This module must remain deterministic.
 * UI confirmation for WARN decisions belongs to the content/UI layer.
 */

import {
  ACTIONS,
  DEFAULT_CONFIG,
  DATA_CATEGORIES,
  SEVERITY,
  PROTECTION_MODES,
  getDefaultAction,
  getDefaultSeverity,
} from "../config/defaults.js";

import {
  SOURCE_TYPES,
} from "../config/constants.js";

/* -------------------------------------------------------------------------- */
/* Constants                                                                  */
/* -------------------------------------------------------------------------- */

const POLICY_ENGINE_VERSION = "1.0.0";

const DECISION_PRIORITY = Object.freeze({
  [ACTIONS.ALLOW]: 0,
  [ACTIONS.WARN]: 1,
  [ACTIONS.MASK]: 2,
  [ACTIONS.BLOCK]: 3,
});

const SEVERITY_PRIORITY = Object.freeze({
  [SEVERITY.LOW]: 1,
  [SEVERITY.MEDIUM]: 2,
  [SEVERITY.HIGH]: 3,
  [SEVERITY.CRITICAL]: 4,
});

const CONFIDENCE_THRESHOLDS = Object.freeze({
  LOW: 0.6,
  MEDIUM: 0.7,
  HIGH: 0.8,
  CRITICAL: 0.9,
});

const DEFAULT_POLICY = Object.freeze({
  enabled: true,
  mode: PROTECTION_MODES.ACTIVE,

  defaultAction: ACTIONS.WARN,

  warnOnUnknown: true,
  blockOnCritical: true,
  blockOnHighRisk: false,

  minimumConfidence: 0.6,
  warningConfidence: 0.7,
  blockConfidence: 0.9,

  riskThresholds: {
    low: 0,
    medium: 30,
    high: 60,
    critical: 85,
  },

  categoryActions: {},
  severityActions: {},

  sourceActions: {},

  platformActions: {},

  allowCategories: [],
  warnCategories: [],
  maskCategories: [],
  blockCategories: [],

  allowRules: [],
  warnRules: [],
  maskRules: [],
  blockRules: [],

  requireMaskForHighRisk: false,
});

/* -------------------------------------------------------------------------- */
/* State                                                                      */
/* -------------------------------------------------------------------------- */

const engineState = {
  initialized: false,
  evaluations: 0,
  allows: 0,
  warnings: 0,
  masks: 0,
  blocks: 0,
  errors: 0,
  lastEvaluationAt: 0,
};

/* -------------------------------------------------------------------------- */
/* Generic helpers                                                            */
/* -------------------------------------------------------------------------- */

function safeString(value) {
  return typeof value === "string"
    ? value
    : "";
}

function normalizeString(value) {
  return safeString(value)
    .trim()
    .toLowerCase();
}

function normalizeAction(value) {
  const action = normalizeString(value);

  if (
    action === ACTIONS.ALLOW ||
    action === ACTIONS.WARN ||
    action === ACTIONS.MASK ||
    action === ACTIONS.BLOCK
  ) {
    return action;
  }

  return null;
}

function normalizeSeverity(value) {
  const severity = normalizeString(value);

  if (
    severity === SEVERITY.LOW ||
    severity === SEVERITY.MEDIUM ||
    severity === SEVERITY.HIGH ||
    severity === SEVERITY.CRITICAL
  ) {
    return severity;
  }

  return SEVERITY.LOW;
}

function normalizeCategory(value) {
  const category = normalizeString(value);

  if (
    Object.values(DATA_CATEGORIES).includes(category)
  ) {
    return category;
  }

  return DATA_CATEGORIES.UNKNOWN;
}

function normalizeSourceType(value) {
  const source = normalizeString(value);

  if (
    Object.values(SOURCE_TYPES).includes(source)
  ) {
    return source;
  }

  return SOURCE_TYPES.UNKNOWN;
}

function normalizeConfidence(value) {
  if (!Number.isFinite(value)) {
    return 0;
  }

  return Math.max(
    0,
    Math.min(1, Number(value)),
  );
}

function normalizeRiskScore(value) {
  if (!Number.isFinite(value)) {
    return 0;
  }

  return Math.max(
    0,
    Math.min(100, Number(value)),
  );
}

function clone(value) {
  if (
    value === null ||
    typeof value !== "object"
  ) {
    return value;
  }

  if (typeof structuredClone === "function") {
    try {
      return structuredClone(value);
    } catch {
      // Continue with manual cloning below.
    }
  }

  if (Array.isArray(value)) {
    return value.map(clone);
  }

  const result = {};

  for (const [key, item] of Object.entries(value)) {
    result[key] = clone(item);
  }

  return result;
}

function isPlainObject(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value)
  );
}

function uniqueStrings(values) {
  if (!Array.isArray(values)) {
    return [];
  }

  const result = [];
  const seen = new Set();

  for (const value of values) {
    const normalized = normalizeString(value);

    if (!normalized || seen.has(normalized)) {
      continue;
    }

    seen.add(normalized);
    result.push(normalized);
  }

  return result;
}

/* -------------------------------------------------------------------------- */
/* Policy normalization                                                        */
/* -------------------------------------------------------------------------- */

function normalizeActionMap(value) {
  if (!isPlainObject(value)) {
    return {};
  }

  const result = {};

  for (const [key, action] of Object.entries(value)) {
    const normalizedAction = normalizeAction(action);

    if (normalizedAction) {
      result[normalizeString(key)] =
        normalizedAction;
    }
  }

  return result;
}

function normalizePolicy(policy = {}) {
  const source =
    isPlainObject(policy)
      ? policy
      : {};

  const categoryActions =
    normalizeActionMap(
      source.categoryActions,
    );

  const severityActions =
    normalizeActionMap(
      source.severityActions,
    );

  const sourceActions =
    normalizeActionMap(
      source.sourceActions,
    );

  const platformActions =
    normalizeActionMap(
      source.platformActions,
    );

  const normalized = {
    ...clone(DEFAULT_POLICY),
    ...clone(source),

    enabled:
      source.enabled !== false,

    mode:
      Object.values(PROTECTION_MODES)
        .includes(source.mode)
        ? source.mode
        : DEFAULT_POLICY.mode,

    defaultAction:
      normalizeAction(
        source.defaultAction,
      ) ??
      DEFAULT_POLICY.defaultAction,

    warnOnUnknown:
      source.warnOnUnknown !== false,

    blockOnCritical:
      source.blockOnCritical !== false,

    blockOnHighRisk:
      source.blockOnHighRisk === true,

    minimumConfidence:
      Number.isFinite(source.minimumConfidence)
        ? Math.max(
            0,
            Math.min(
              1,
              source.minimumConfidence,
            ),
          )
        : DEFAULT_POLICY.minimumConfidence,

    warningConfidence:
      Number.isFinite(source.warningConfidence)
        ? Math.max(
            0,
            Math.min(
              1,
              source.warningConfidence,
            ),
          )
        : DEFAULT_POLICY.warningConfidence,

    blockConfidence:
      Number.isFinite(source.blockConfidence)
        ? Math.max(
            0,
            Math.min(
              1,
              source.blockConfidence,
            ),
          )
        : DEFAULT_POLICY.blockConfidence,

    categoryActions,
    severityActions,
    sourceActions,
    platformActions,

    allowCategories:
      uniqueStrings(
        source.allowCategories,
      ),

    warnCategories:
      uniqueStrings(
        source.warnCategories,
      ),

    maskCategories:
      uniqueStrings(
        source.maskCategories,
      ),

    blockCategories:
      uniqueStrings(
        source.blockCategories,
      ),

    allowRules:
      uniqueStrings(
        source.allowRules,
      ),

    warnRules:
      uniqueStrings(
        source.warnRules,
      ),

    maskRules:
      uniqueStrings(
        source.maskRules,
      ),

    blockRules:
      uniqueStrings(
        source.blockRules,
      ),

    requireMaskForHighRisk:
      source.requireMaskForHighRisk === true,
  };

  if (
    isPlainObject(source.riskThresholds)
  ) {
    normalized.riskThresholds = {
      low:
        Number.isFinite(
          source.riskThresholds.low,
        )
          ? source.riskThresholds.low
          : DEFAULT_POLICY.riskThresholds.low,

      medium:
        Number.isFinite(
          source.riskThresholds.medium,
        )
          ? source.riskThresholds.medium
          : DEFAULT_POLICY.riskThresholds.medium,

      high:
        Number.isFinite(
          source.riskThresholds.high,
        )
          ? source.riskThresholds.high
          : DEFAULT_POLICY.riskThresholds.high,

      critical:
        Number.isFinite(
          source.riskThresholds.critical,
        )
          ? source.riskThresholds.critical
          : DEFAULT_POLICY.riskThresholds.critical,
    };
  } else {
    normalized.riskThresholds =
      clone(
        DEFAULT_POLICY.riskThresholds,
      );
  }

  return normalized;
}

/* -------------------------------------------------------------------------- */
/* Finding normalization                                                       */
/* -------------------------------------------------------------------------- */

function normalizeFinding(finding) {
  if (
    !finding ||
    typeof finding !== "object"
  ) {
    return null;
  }

  const ruleId = normalizeString(
    finding.ruleId ??
    finding.id,
  );

  const category = normalizeCategory(
    finding.category,
  );

  const severity = normalizeSeverity(
    finding.severity ??
    getDefaultSeverity(category),
  );

  const confidence =
    normalizeConfidence(
      finding.confidence,
    );

  return {
    ...finding,

    ruleId:
      ruleId ||
      "unknown-rule",

    category,

    severity,

    confidence,

    source:
      normalizeSourceType(
        finding.source,
      ),

    start:
      Number.isFinite(finding.start)
        ? finding.start
        : null,

    end:
      Number.isFinite(finding.end)
        ? finding.end
        : null,
  };
}

function normalizeFindings(findings) {
  if (!Array.isArray(findings)) {
    return [];
  }

  return findings
    .map(normalizeFinding)
    .filter(Boolean);
}

/* -------------------------------------------------------------------------- */
/* Rule matching                                                              */
/* -------------------------------------------------------------------------- */

function matchesList(value, list) {
  const normalized =
    normalizeString(value);

  return (
    normalized.length > 0 &&
    Array.isArray(list) &&
    list.includes(normalized)
  );
}

function getRuleOverride(
  finding,
  policy,
) {
  const ruleId =
    normalizeString(
      finding.ruleId,
    );

  if (
    matchesList(
      ruleId,
      policy.blockRules,
    )
  ) {
    return ACTIONS.BLOCK;
  }

  if (
    matchesList(
      ruleId,
      policy.maskRules,
    )
  ) {
    return ACTIONS.MASK;
  }

  if (
    matchesList(
      ruleId,
      policy.warnRules,
    )
  ) {
    return ACTIONS.WARN;
  }

  if (
    matchesList(
      ruleId,
      policy.allowRules,
    )
  ) {
    return ACTIONS.ALLOW;
  }

  return null;
}

function getCategoryOverride(
  finding,
  policy,
) {
  const category =
    normalizeCategory(
      finding.category,
    );

  if (
    policy.blockCategories.includes(
      category,
    )
  ) {
    return ACTIONS.BLOCK;
  }

  if (
    policy.maskCategories.includes(
      category,
    )
  ) {
    return ACTIONS.MASK;
  }

  if (
    policy.warnCategories.includes(
      category,
    )
  ) {
    return ACTIONS.WARN;
  }

  if (
    policy.allowCategories.includes(
      category,
    )
  ) {
    return ACTIONS.ALLOW;
  }

  return null;
}

function getMapAction(
  value,
  actionMap,
) {
  const normalized =
    normalizeString(value);

  if (
    !normalized ||
    !isPlainObject(actionMap)
  ) {
    return null;
  }

  return normalizeAction(
    actionMap[normalized],
  );
}

/* -------------------------------------------------------------------------- */
/* Confidence policy                                                          */
/* -------------------------------------------------------------------------- */

function isBelowMinimumConfidence(
  finding,
  policy,
) {
  return (
    finding.confidence <
    policy.minimumConfidence
  );
}

function isHighConfidence(
  finding,
  policy,
) {
  return (
    finding.confidence >=
    policy.blockConfidence
  );
}

function getConfidenceAction(
  finding,
  policy,
  baseAction,
) {
  if (
    isBelowMinimumConfidence(
      finding,
      policy,
    )
  ) {
    if (
      baseAction === ACTIONS.BLOCK ||
      baseAction === ACTIONS.MASK
    ) {
      return ACTIONS.WARN;
    }

    if (
      policy.warnOnUnknown
    ) {
      return ACTIONS.WARN;
    }

    return ACTIONS.ALLOW;
  }

  if (
    baseAction === ACTIONS.BLOCK &&
    !isHighConfidence(
      finding,
      policy,
    )
  ) {
    return ACTIONS.WARN;
  }

  return baseAction;
}

/* -------------------------------------------------------------------------- */
/* Severity policy                                                             */
/* -------------------------------------------------------------------------- */

function getSeverityAction(
  finding,
  policy,
) {
  const severity =
    normalizeSeverity(
      finding.severity,
    );

  const configured =
    getMapAction(
      severity,
      policy.severityActions,
    );

  if (configured) {
    return configured;
  }

  if (
    severity === SEVERITY.CRITICAL
  ) {
    if (
      policy.blockOnCritical
    ) {
      return ACTIONS.BLOCK;
    }

    return ACTIONS.WARN;
  }

  if (
    severity === SEVERITY.HIGH
  ) {
    return ACTIONS.WARN;
  }

  if (
    severity === SEVERITY.MEDIUM
  ) {
    return ACTIONS.WARN;
  }

  return ACTIONS.ALLOW;
}

/* -------------------------------------------------------------------------- */
/* Default category policy                                                     */
/* -------------------------------------------------------------------------- */

function getCategoryDefaultAction(
  category,
) {
  try {
    return getDefaultAction(
      normalizeCategory(category),
    );
  } catch {
    return ACTIONS.WARN;
  }
}

/* -------------------------------------------------------------------------- */
/* Individual finding decision                                                 */
/* -------------------------------------------------------------------------- */

function evaluateFinding(
  finding,
  policy,
  context,
) {
  const normalized =
    normalizeFinding(finding);

  if (!normalized) {
    return {
      action: ACTIONS.ALLOW,
      reason: "invalid-finding",
      confidence: 0,
      severity: SEVERITY.LOW,
      category: DATA_CATEGORIES.UNKNOWN,
      ruleId: "unknown-rule",
    };
  }

  const category =
    normalized.category;

  const severity =
    normalized.severity;

  const ruleId =
    normalized.ruleId;

  let action = null;
  let reason = null;

  /*
   * Priority 1:
   * Explicit rule override.
   */
  action =
    getRuleOverride(
      normalized,
      policy,
    );

  if (action) {
    reason = "rule-override";
  }

  /*
   * Priority 2:
   * Explicit category override.
   */
  if (!action) {
    action =
      getCategoryOverride(
        normalized,
        policy,
      );

    if (action) {
      reason =
        "category-override";
    }
  }

  /*
   * Priority 3:
   * Platform-specific override.
   */
  if (!action) {
    const platformId =
      normalizeString(
        context.platformId,
      );

    const platformAction =
      getMapAction(
        platformId,
        policy.platformActions,
      );

    if (platformAction) {
      action =
        platformAction;

      reason =
        "platform-override";
    }
  }

  /*
   * Priority 4:
   * Source-specific override.
   */
  if (!action) {
    const sourceAction =
      getMapAction(
        normalized.source,
        policy.sourceActions,
      );

    if (sourceAction) {
      action =
        sourceAction;

      reason =
        "source-override";
    }
  }

  /*
   * Priority 5:
   * Category action map.
   */
  if (!action) {
    const categoryAction =
      getMapAction(
        category,
        policy.categoryActions,
      );

    if (categoryAction) {
      action =
        categoryAction;

      reason =
        "category-policy";
    }
  }

  /*
   * Priority 6:
   * Severity action map.
   */
  if (!action) {
    const severityAction =
      getSeverityAction(
        normalized,
        policy,
      );

    if (severityAction) {
      action =
        severityAction;

      reason =
        "severity-policy";
    }
  }

  /*
   * Priority 7:
   * Default category policy.
   */
  if (!action) {
    action =
      getCategoryDefaultAction(
        category,
      );

    reason =
      "category-default";
  }

  /*
   * Unknown category is never silently ignored
   * when unknown protection is enabled.
   */
  if (
    category ===
      DATA_CATEGORIES.UNKNOWN &&
    policy.warnOnUnknown &&
    action === ACTIONS.ALLOW
  ) {
    action =
      ACTIONS.WARN;

    reason =
      "unknown-category";
  }

  /*
   * Apply confidence requirements after
   * explicit policy selection.
   */
  const confidenceAction =
    getConfidenceAction(
      normalized,
      policy,
      action,
    );

  if (
    confidenceAction !== action
  ) {
    action =
      confidenceAction;

    reason =
      "confidence-threshold";
  }

  /*
   * Critical findings can never become ALLOW
   * when critical blocking is enabled.
   */
  if (
    severity === SEVERITY.CRITICAL &&
    policy.blockOnCritical
  ) {
    if (
      normalized.confidence >=
      policy.minimumConfidence
    ) {
      action =
        ACTIONS.BLOCK;

      reason =
        "critical-severity";
    }
  }

  /*
   * High confidence block override.
   */
  if (
    action === ACTIONS.BLOCK &&
    normalized.confidence <
      policy.minimumConfidence
  ) {
    action =
      ACTIONS.WARN;

    reason =
      "block-confidence-too-low";
  }

  return {
    action,
    reason,

    ruleId,
    category,
    severity,
    confidence:
      normalized.confidence,

    source:
      normalized.source,

    start:
      normalized.start,

    end:
      normalized.end,
  };
}

/* -------------------------------------------------------------------------- */
/* Risk-level handling                                                         */
/* -------------------------------------------------------------------------- */

function getRiskLevelFromScore(
  score,
  policy,
) {
  const risk =
    normalizeRiskScore(score);

  const thresholds =
    policy.riskThresholds;

  if (
    risk >=
    thresholds.critical
  ) {
    return "critical";
  }

  if (
    risk >=
    thresholds.high
  ) {
    return "high";
  }

  if (
    risk >=
    thresholds.medium
  ) {
    return "medium";
  }

  return "low";
}

function getRiskAction(
  risk,
  policy,
) {
  const score =
    normalizeRiskScore(
      risk?.score,
    );

  const level =
    normalizeString(
      risk?.level,
    ) ||
    getRiskLevelFromScore(
      score,
      policy,
    );

  if (
    level === "critical"
  ) {
    return ACTIONS.BLOCK;
  }

  if (
    level === "high"
  ) {
    if (
      policy.blockOnHighRisk
    ) {
      return ACTIONS.BLOCK;
    }

    if (
      policy.requireMaskForHighRisk
    ) {
      return ACTIONS.MASK;
    }

    return ACTIONS.WARN;
  }

  if (
    level === "medium"
  ) {
    return ACTIONS.WARN;
  }

  return null;
}

/* -------------------------------------------------------------------------- */
/* Decision priority                                                           */
/* -------------------------------------------------------------------------- */

function getActionPriority(
  action,
) {
  return (
    DECISION_PRIORITY[
      normalizeAction(action)
    ] ??
    DECISION_PRIORITY[
      ACTIONS.ALLOW
    ]
  );
}

function getHighestPriorityAction(
  actions,
) {
  let selected =
    ACTIONS.ALLOW;

  for (const action of actions) {
    const normalized =
      normalizeAction(action);

    if (!normalized) {
      continue;
    }

    if (
      getActionPriority(
        normalized,
      ) >
      getActionPriority(
        selected,
      )
    ) {
      selected =
        normalized;
    }
  }

  return selected;
}

/* -------------------------------------------------------------------------- */
/* Final policy decision                                                       */
/* -------------------------------------------------------------------------- */

export function evaluatePolicy(
  scanResult,
  context = {},
  policyInput = {},
) {
  const startedAt =
    Date.now();

  engineState.evaluations += 1;
  engineState.lastEvaluationAt =
    startedAt;

  try {
    const policy =
      normalizePolicy(
        policyInput,
      );

    const normalizedContext =
      isPlainObject(context)
        ? context
        : {};

    /*
     * Protection disabled.
     */
    if (
      !policy.enabled ||
      policy.mode ===
        PROTECTION_MODES.DISABLED
    ) {
      engineState.allows += 1;

      return createPolicyResult({
        action: ACTIONS.ALLOW,
        reason: "protection-disabled",
        findings: [],
        evaluatedFindings: [],
        risk: scanResult?.risk ?? null,
        context: normalizedContext,
        startedAt,
      });
    }

    /*
     * Monitor mode never actively blocks.
     * We still evaluate the policy so the UI can show
     * what would have happened.
     */
    const monitorMode =
      policy.mode ===
      PROTECTION_MODES.MONITOR;

    const findings =
      normalizeFindings(
        scanResult?.findings,
      );

    const findingDecisions = [];

    for (const finding of findings) {
      const decision =
        evaluateFinding(
          finding,
          policy,
          normalizedContext,
        );

      findingDecisions.push({
        ...decision,

        /*
         * Keep the original finding locally so the
         * mask engine can later use offsets and values.
         */
        finding,
      });
    }

    const findingActions =
      findingDecisions.map(
        (item) => item.action,
      );

    let action =
      getHighestPriorityAction(
        findingActions,
      );

    let reason =
      findingDecisions.length > 0
        ? "finding-policy"
        : "no-sensitive-findings";

    /*
     * Aggregate risk can escalate the decision.
     */
    const risk =
      scanResult?.risk ?? null;

    const riskAction =
      getRiskAction(
        risk,
        policy,
      );

    if (riskAction) {
      const currentPriority =
        getActionPriority(action);

      const riskPriority =
        getActionPriority(
          riskAction,
        );

      if (
        riskPriority >
        currentPriority
      ) {
        action =
          riskAction;

        reason =
          "aggregate-risk";
      }
    }

    /*
     * Critical finding override.
     */
    const hasCriticalFinding =
      findingDecisions.some(
        (item) =>
          item.severity ===
          SEVERITY.CRITICAL &&
          item.confidence >=
            policy.minimumConfidence,
      );

    if (
      hasCriticalFinding &&
      policy.blockOnCritical
    ) {
      action =
        ACTIONS.BLOCK;

      reason =
        "critical-finding";
    }

    /*
     * Monitor mode changes the enforcement action
     * without losing the calculated action.
     */
    const enforcedAction =
      action;

    if (monitorMode) {
      action =
        ACTIONS.ALLOW;
    }

    /*
     * No findings and no risk should be ALLOW.
     */
    if (
      findings.length === 0 &&
      !riskAction
    ) {
      action =
        ACTIONS.ALLOW;

      reason =
        "no-sensitive-findings";
    }

    updateDecisionCounters(
      action,
    );

    return createPolicyResult({
      action,
      enforcedAction,
      reason,
      findings,
      evaluatedFindings:
        findingDecisions,
      risk,
      context:
        normalizedContext,
      startedAt,
      monitorMode,
    });
  } catch {
    engineState.errors += 1;

    /*
     * Fail closed for policy-engine errors.
     * This protects against accidental data transfer
     * when the policy layer itself cannot determine
     * a safe decision.
     */
    engineState.blocks += 1;

    return createPolicyResult({
      action: ACTIONS.BLOCK,
      enforcedAction: ACTIONS.BLOCK,
      reason: "policy-engine-error",
      findings: [],
      evaluatedFindings: [],
      risk: scanResult?.risk ?? null,
      context:
        isPlainObject(context)
          ? context
          : {},
      startedAt,
      error: true,
    });
  }
}

/* -------------------------------------------------------------------------- */
/* Policy result                                                               */
/* -------------------------------------------------------------------------- */

function createPolicyResult({
  action,
  enforcedAction = action,
  reason,
  findings,
  evaluatedFindings,
  risk,
  context,
  startedAt,
  monitorMode = false,
  error = false,
}) {
  const safeAction =
    normalizeAction(action) ??
    ACTIONS.BLOCK;

  const safeEnforcedAction =
    normalizeAction(
      enforcedAction,
    ) ??
    ACTIONS.BLOCK;

  const durationMs =
    Math.max(
      0,
      Date.now() -
        startedAt,
    );

  const severityCounts = {
    low: 0,
    medium: 0,
    high: 0,
    critical: 0,
  };

  for (const item of evaluatedFindings) {
    const severity =
      normalizeSeverity(
        item.severity,
      );

    if (
      Object.prototype.hasOwnProperty.call(
        severityCounts,
        severity,
      )
    ) {
      severityCounts[
        severity
      ] += 1;
    }
  }

  return {
    engineVersion:
      POLICY_ENGINE_VERSION,

    action:
      safeAction,

    enforcedAction:
      safeEnforcedAction,

    reason,

    monitorMode,

    error,

    requiresUserConfirmation:
      safeAction === ACTIONS.WARN,

    shouldMask:
      safeAction === ACTIONS.MASK,

    shouldBlock:
      safeAction === ACTIONS.BLOCK,

    shouldAllow:
      safeAction === ACTIONS.ALLOW,

    risk: risk
      ? {
          score:
            normalizeRiskScore(
              risk.score,
            ),

          level:
            normalizeString(
              risk.level,
            ),

          label:
            safeString(
              risk.label,
            ),

          findingCount:
            Number.isFinite(
              risk.findingCount,
            )
              ? risk.findingCount
              : findings.length,
        }
      : null,

    statistics: {
      findings:
        findings.length,

      low:
        severityCounts.low,

      medium:
        severityCounts.medium,

      high:
        severityCounts.high,

      critical:
        severityCounts.critical,
    },

    /*
     * Context contains only metadata.
     * Raw prompt/file/clipboard data must never be
     * placed here.
     */
    context: {
      platformId:
        normalizeString(
          context?.platformId,
        ),

      platformCategory:
        normalizeString(
          context?.platformCategory,
        ),

      hostname:
        normalizeString(
          context?.hostname,
        ),

      sourceType:
        normalizeSourceType(
          context?.sourceType,
        ),

      inputType:
        normalizeString(
          context?.inputType,
        ),
    },

    /*
     * Findings are intentionally kept in the local
     * content context for policy and masking.
     */
    findings:

      Array.isArray(findings)
        ? findings
        : [],

    evaluatedFindings:

      Array.isArray(
        evaluatedFindings,
      )
        ? evaluatedFindings
        : [],

    durationMs,
  };
}

/* -------------------------------------------------------------------------- */
/* Decision counters                                                           */
/* -------------------------------------------------------------------------- */

function updateDecisionCounters(
  action,
) {
  switch (action) {
    case ACTIONS.ALLOW:
      engineState.allows += 1;
      break;

    case ACTIONS.WARN:
      engineState.warnings += 1;
      break;

    case ACTIONS.MASK:
      engineState.masks += 1;
      break;

    case ACTIONS.BLOCK:
      engineState.blocks += 1;
      break;

    default:
      engineState.errors += 1;
      break;
  }
}

/* -------------------------------------------------------------------------- */
/* Convenience policy functions                                               */
/* -------------------------------------------------------------------------- */

export function shouldAllow(
  scanResult,
  context = {},
  policy = {},
) {
  return (
    evaluatePolicy(
      scanResult,
      context,
      policy,
    ).action ===
    ACTIONS.ALLOW
  );
}

export function shouldWarn(
  scanResult,
  context = {},
  policy = {},
) {
  return (
    evaluatePolicy(
      scanResult,
      context,
      policy,
    ).action ===
    ACTIONS.WARN
  );
}

export function shouldMask(
  scanResult,
  context = {},
  policy = {},
) {
  return (
    evaluatePolicy(
      scanResult,
      context,
      policy,
    ).action ===
    ACTIONS.MASK
  );
}

export function shouldBlock(
  scanResult,
  context = {},
  policy = {},
) {
  return (
    evaluatePolicy(
      scanResult,
      context,
      policy,
    ).action ===
    ACTIONS.BLOCK
  );
}

/* -------------------------------------------------------------------------- */
/* Finding-level convenience functions                                        */
/* -------------------------------------------------------------------------- */

export function evaluateFindingPolicy(
  finding,
  context = {},
  policy = {},
) {
  const normalizedPolicy =
    normalizePolicy(
      policy,
    );

  const normalizedFinding =
    normalizeFinding(
      finding,
    );

  if (!normalizedFinding) {
    return {
      action: ACTIONS.BLOCK,
      reason: "invalid-finding",
    };
  }

  return evaluateFinding(
    normalizedFinding,
    normalizedPolicy,
    context,
  );
}

/* -------------------------------------------------------------------------- */
/* Risk helpers                                                                */
/* -------------------------------------------------------------------------- */

export function getPolicyRiskAction(
  risk,
  policy = {},
) {
  return getRiskAction(
    risk,
    normalizePolicy(
      policy,
    ),
  );
}

export function getRiskLevel(
  score,
  policy = {},
) {
  return getRiskLevelFromScore(
    score,
    normalizePolicy(
      policy,
    ),
  );
}

/* -------------------------------------------------------------------------- */
/* Action helpers                                                              */
/* -------------------------------------------------------------------------- */

export function compareActions(
  first,
  second,
) {
  const firstPriority =
    getActionPriority(first);

  const secondPriority =
    getActionPriority(second);

  if (
    firstPriority <
    secondPriority
  ) {
    return -1;
  }

  if (
    firstPriority >
    secondPriority
  ) {
    return 1;
  }

  return 0;
}

export function getHigherPriorityAction(
  first,
  second,
) {
  return compareActions(
    first,
    second,
  ) >= 0
    ? normalizeAction(first) ??
        ACTIONS.ALLOW
    : normalizeAction(second) ??
        ACTIONS.ALLOW;
}

export function getDecisionPriority(
  action,
) {
  return getActionPriority(
    action,
  );
}

/* -------------------------------------------------------------------------- */
/* Configuration                                                               */
/* -------------------------------------------------------------------------- */

export function getDefaultPolicy() {
  return clone(
    DEFAULT_POLICY,
  );
}

export function normalizePolicyConfiguration(
  policy,
) {
  return normalizePolicy(
    policy,
  );
}

export function validatePolicyConfiguration(
  policyInput = {},
) {
  const errors = [];

  const policy =
    normalizePolicy(
      policyInput,
    );

  if (
    !Object.values(
      ACTIONS,
    ).includes(
      policy.defaultAction,
    )
  ) {
    errors.push(
      "Invalid default action.",
    );
  }

  if (
    policy.minimumConfidence <
      0 ||
    policy.minimumConfidence >
      1
  ) {
    errors.push(
      "minimumConfidence must be between 0 and 1.",
    );
  }

  if (
    policy.warningConfidence <
      0 ||
    policy.warningConfidence >
      1
  ) {
    errors.push(
      "warningConfidence must be between 0 and 1.",
    );
  }

  if (
    policy.blockConfidence <
      0 ||
    policy.blockConfidence >
      1
  ) {
    errors.push(
      "blockConfidence must be between 0 and 1.",
    );
  }

  if (
    policy.minimumConfidence >
    policy.warningConfidence
  ) {
    errors.push(
      "minimumConfidence cannot exceed warningConfidence.",
    );
  }

  if (
    policy.warningConfidence >
    policy.blockConfidence
  ) {
    errors.push(
      "warningConfidence cannot exceed blockConfidence.",
    );
  }

  const thresholds =
    policy.riskThresholds;

  if (
    thresholds.low >
    thresholds.medium
  ) {
    errors.push(
      "Risk low threshold cannot exceed medium threshold.",
    );
  }

  if (
    thresholds.medium >
    thresholds.high
  ) {
    errors.push(
      "Risk medium threshold cannot exceed high threshold.",
    );
  }

  if (
    thresholds.high >
    thresholds.critical
  ) {
    errors.push(
      "Risk high threshold cannot exceed critical threshold.",
    );
  }

  return {
    valid:
      errors.length === 0,

    errors,

    normalizedPolicy:
      policy,
  };
}

/* -------------------------------------------------------------------------- */
/* Policy presets                                                              */
/* -------------------------------------------------------------------------- */

export function createStrictPolicy() {
  return normalizePolicy({
    ...DEFAULT_POLICY,

    defaultAction:
      ACTIONS.WARN,

    blockOnCritical:
      true,

    blockOnHighRisk:
      true,

    minimumConfidence:
      0.6,

    warningConfidence:
      0.7,

    blockConfidence:
      0.8,

    requireMaskForHighRisk:
      false,
  });
}

export function createBalancedPolicy() {
  return normalizePolicy({
    ...DEFAULT_POLICY,

    defaultAction:
      ACTIONS.WARN,

    blockOnCritical:
      true,

    blockOnHighRisk:
      false,

    minimumConfidence:
      0.6,

    warningConfidence:
      0.7,

    blockConfidence:
      0.9,

    requireMaskForHighRisk:
      false,
  });
}

export function createMonitorPolicy() {
  return normalizePolicy({
    ...DEFAULT_POLICY,

    mode:
      PROTECTION_MODES.MONITOR,

    defaultAction:
      ACTIONS.WARN,

    blockOnCritical:
      true,

    blockOnHighRisk:
      true,
  });
}

/* -------------------------------------------------------------------------- */
/* Policy summary                                                              */
/* -------------------------------------------------------------------------- */

export function getPolicySummary(
  policyInput = {},
) {
  const policy =
    normalizePolicy(
      policyInput,
    );

  return {
    engineVersion:
      POLICY_ENGINE_VERSION,

    enabled:
      policy.enabled,

    mode:
      policy.mode,

    defaultAction:
      policy.defaultAction,

    blockOnCritical:
      policy.blockOnCritical,

    blockOnHighRisk:
      policy.blockOnHighRisk,

    minimumConfidence:
      policy.minimumConfidence,

    warningConfidence:
      policy.warningConfidence,

    blockConfidence:
      policy.blockConfidence,

    riskThresholds:
      clone(
        policy.riskThresholds,
      ),

    categoryOverrides:
      Object.keys(
        policy.categoryActions,
      ).length,

    severityOverrides:
      Object.keys(
        policy.severityActions,
      ).length,

    sourceOverrides:
      Object.keys(
        policy.sourceActions,
      ).length,

    platformOverrides:
      Object.keys(
        policy.platformActions,
      ).length,

    ruleOverrides:
      policy.allowRules.length +
      policy.warnRules.length +
      policy.maskRules.length +
      policy.blockRules.length,
  };
}

/* -------------------------------------------------------------------------- */
/* Engine state                                                                */
/* -------------------------------------------------------------------------- */

export function initializePolicyEngine() {
  engineState.initialized = true;

  return {
    initialized: true,
    engineVersion:
      POLICY_ENGINE_VERSION,
  };
}

export function destroyPolicyEngine() {
  engineState.initialized = false;
}

export function getPolicyEngineStats() {
  return {
    engineVersion:
      POLICY_ENGINE_VERSION,

    initialized:
      engineState.initialized,

    evaluations:
      engineState.evaluations,

    allows:
      engineState.allows,

    warnings:
      engineState.warnings,

    masks:
      engineState.masks,

    blocks:
      engineState.blocks,

    errors:
      engineState.errors,

    lastEvaluationAt:
      engineState.lastEvaluationAt,
  };
}

export function resetPolicyEngineStats() {
  engineState.evaluations = 0;
  engineState.allows = 0;
  engineState.warnings = 0;
  engineState.masks = 0;
  engineState.blocks = 0;
  engineState.errors = 0;
  engineState.lastEvaluationAt = 0;
}

/* -------------------------------------------------------------------------- */
/* Diagnostics                                                                 */
/* -------------------------------------------------------------------------- */

export function getPolicyEngineDiagnostics() {
  return {
    engineVersion:
      POLICY_ENGINE_VERSION,

    initialized:
      engineState.initialized,

    localOnly:
      true,

    networkAccess:
      false,

    chromeApiAccess:
      false,

    persistentSensitiveData:
      false,

    deterministic:
      true,

    supportedActions: [
      ACTIONS.ALLOW,
      ACTIONS.WARN,
      ACTIONS.MASK,
      ACTIONS.BLOCK,
    ],

    supportedModes: [
      PROTECTION_MODES.ACTIVE,
      PROTECTION_MODES.MONITOR,
      PROTECTION_MODES.DISABLED,
    ],

    severityPriority:
      clone(
        SEVERITY_PRIORITY,
      ),

    decisionPriority:
      clone(
        DECISION_PRIORITY,
      ),

    confidenceThresholds:
      clone(
        CONFIDENCE_THRESHOLDS,
      ),

    stats:
      getPolicyEngineStats(),
  };
}

/* -------------------------------------------------------------------------- */
/* Safe diagnostic result                                                      */
/* -------------------------------------------------------------------------- */

export function getSafePolicyResult(
  result,
) {
  if (
    !result ||
    typeof result !== "object"
  ) {
    return null;
  }

  return {
    engineVersion:
      result.engineVersion,

    action:
      result.action,

    enforcedAction:
      result.enforcedAction,

    reason:
      result.reason,

    monitorMode:
      result.monitorMode === true,

    error:
      result.error === true,

    requiresUserConfirmation:
      result.requiresUserConfirmation === true,

    shouldMask:
      result.shouldMask === true,

    shouldBlock:
      result.shouldBlock === true,

    shouldAllow:
      result.shouldAllow === true,

    risk:
      result.risk
        ? {
            score:
              result.risk.score,

            level:
              result.risk.level,

            label:
              result.risk.label,

            findingCount:
              result.risk.findingCount,
          }
        : null,

    statistics:
      result.statistics
        ? clone(
            result.statistics,
          )
        : null,

    context:
      result.context
        ? clone(
            result.context,
          )
        : null,

    durationMs:
      result.durationMs,
  };
}

/* -------------------------------------------------------------------------- */
/* Default initialization                                                      */
/* -------------------------------------------------------------------------- */

initializePolicyEngine();
