/**
 * SanitizerPro
 * Local risk scoring engine.
 *
 * Responsibilities:
 * - Calculate deterministic risk scores from matcher findings.
 * - Account for severity, confidence, category, finding count,
 *   and high-risk categories.
 * - Produce LOW / MEDIUM / HIGH / CRITICAL risk levels.
 * - Provide category and severity summaries.
 * - Never make ALLOW / WARN / MASK / BLOCK decisions.
 * - Never access Chrome APIs.
 * - Never perform network requests.
 * - Never persist or transmit sensitive content.
 *
 * Policy enforcement belongs to:
 *   src/policy/policy-engine.js
 */

import {
  DATA_CATEGORIES,
  SEVERITY,
  RISK_THRESHOLDS,
} from "../config/defaults.js";

const RISK_SCORE_VERSION = 1;

const RISK_LEVELS = Object.freeze({
  LOW: "low",
  MEDIUM: "medium",
  HIGH: "high",
  CRITICAL: "critical",
});

const DEFAULT_RISK_THRESHOLDS = Object.freeze({
  low:
    Number.isFinite(RISK_THRESHOLDS?.low)
      ? RISK_THRESHOLDS.low
      : 0,

  medium:
    Number.isFinite(RISK_THRESHOLDS?.medium)
      ? RISK_THRESHOLDS.medium
      : 30,

  high:
    Number.isFinite(RISK_THRESHOLDS?.high)
      ? RISK_THRESHOLDS.high
      : 60,

  critical:
    Number.isFinite(RISK_THRESHOLDS?.critical)
      ? RISK_THRESHOLDS.critical
      : 85,
});

const DEFAULT_WEIGHTS = Object.freeze({
  severity: 0.45,
  confidence: 0.30,
  category: 0.15,
  repetition: 0.10,
});

const SEVERITY_SCORES = Object.freeze({
  low: 15,
  medium: 35,
  high: 65,
  critical: 95,
});

const CATEGORY_SCORES = Object.freeze({
  secret: 100,
  credential: 100,
  private_key: 100,
  token: 100,
  api_key: 100,
  password: 100,

  credit_card: 100,
  bank_account: 95,
  iban: 95,

  database: 95,

  health: 85,

  financial: 80,

  internal: 75,
  confidential: 80,

  infrastructure: 75,

  pii: 65,
  email: 45,
  phone: 50,
  address: 55,
  person_name: 30,

  source_code: 55,

  unknown: 10,
});

const CRITICAL_CATEGORIES = new Set([
  DATA_CATEGORIES?.SECRET ?? "secret",
  DATA_CATEGORIES?.CREDENTIAL ?? "credential",
  DATA_CATEGORIES?.PRIVATE_KEY ?? "private_key",
  DATA_CATEGORIES?.TOKEN ?? "token",
  DATA_CATEGORIES?.API_KEY ?? "api_key",
  DATA_CATEGORIES?.PASSWORD ?? "password",
  DATA_CATEGORIES?.CREDIT_CARD ?? "credit_card",
  DATA_CATEGORIES?.BANK_ACCOUNT ?? "bank_account",
  DATA_CATEGORIES?.IBAN ?? "iban",
  DATA_CATEGORIES?.DATABASE ?? "database",
]);

const HIGH_RISK_CATEGORIES = new Set([
  DATA_CATEGORIES?.HEALTH ?? "health",
  DATA_CATEGORIES?.FINANCIAL ?? "financial",
  DATA_CATEGORIES?.INTERNAL ?? "internal",
  DATA_CATEGORIES?.CONFIDENTIAL ?? "confidential",
  DATA_CATEGORIES?.INFRASTRUCTURE ?? "infrastructure",
]);

const SEVERITY_RANK = Object.freeze({
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
});

const RISK_RANK = Object.freeze({
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
});

const MAX_SCORE = 100;

const MAX_FINDINGS_FOR_REPETITION = 10;

const DEFAULT_CONFIDENCE = 0.75;

const MIN_CONFIDENCE = 0;

const MAX_CONFIDENCE = 1;

function isObject(value) {
  return (
    value !== null &&
    typeof value === "object"
  );
}

function isFiniteNumber(value) {
  return Number.isFinite(value);
}

function clamp(
  value,
  minimum,
  maximum
) {
  if (!Number.isFinite(value)) {
    return minimum;
  }

  return Math.min(
    maximum,
    Math.max(minimum, value)
  );
}

function normalizeConfidence(
  value
) {
  return clamp(
    Number.isFinite(value)
      ? value
      : DEFAULT_CONFIDENCE,
    MIN_CONFIDENCE,
    MAX_CONFIDENCE
  );
}

function normalizeSeverity(
  severity
) {
  if (
    typeof severity !==
    "string"
  ) {
    return SEVERITY?.LOW ?? "low";
  }

  const normalized =
    severity
      .trim()
      .toLowerCase();

  if (
    Object.prototype.hasOwnProperty.call(
      SEVERITY_RANK,
      normalized
    )
  ) {
    return normalized;
  }

  return SEVERITY?.LOW ?? "low";
}

function normalizeCategory(
  category
) {
  if (
    typeof category !==
    "string"
  ) {
    return (
      DATA_CATEGORIES?.UNKNOWN ??
      "unknown"
    );
  }

  const normalized =
    category
      .trim()
      .toLowerCase();

  return normalized || (
    DATA_CATEGORIES?.UNKNOWN ??
    "unknown"
  );
}

function severityRank(
  severity
) {
  return (
    SEVERITY_RANK[
      normalizeSeverity(severity)
    ] ?? 0
  );
}

function riskRank(
  risk
) {
  return (
    RISK_RANK[
      typeof risk === "string"
        ? risk.toLowerCase()
        : ""
    ] ?? 0
  );
}

function normalizeThresholds(
  thresholds = {}
) {
  const merged = {
    ...DEFAULT_RISK_THRESHOLDS,
  };

  if (
    isObject(thresholds)
  ) {
    for (
      const level of Object.keys(
        merged
      )
    ) {
      if (
        Number.isFinite(
          thresholds[level]
        )
      ) {
        merged[level] = clamp(
          thresholds[level],
          0,
          MAX_SCORE
        );
      }
    }
  }

  merged.low = 0;

  merged.medium = Math.max(
    merged.low,
    merged.medium
  );

  merged.high = Math.max(
    merged.medium,
    merged.high
  );

  merged.critical = Math.max(
    merged.high,
    merged.critical
  );

  return merged;
}

function normalizeWeights(
  weights = {}
) {
  const result = {
    ...DEFAULT_WEIGHTS,
  };

  if (
    isObject(weights)
  ) {
    for (
      const key of Object.keys(
        result
      )
    ) {
      if (
        Number.isFinite(
          weights[key]
        ) &&
        weights[key] >= 0
      ) {
        result[key] = weights[key];
      }
    }
  }

  const total =
    Object.values(result)
      .reduce(
        (sum, value) =>
          sum + value,
        0
      );

  if (
    total <= 0
  ) {
    return {
      ...DEFAULT_WEIGHTS,
    };
  }

  return {
    severity:
      result.severity / total,

    confidence:
      result.confidence / total,

    category:
      result.category / total,

    repetition:
      result.repetition / total,
  };
}

function getSeverityScore(
  severity
) {
  return (
    SEVERITY_SCORES[
      normalizeSeverity(
        severity
      )
    ] ?? SEVERITY_SCORES.low
  );
}

function getCategoryScore(
  category
) {
  return (
    CATEGORY_SCORES[
      normalizeCategory(
        category
      )
    ] ??
    CATEGORY_SCORES.unknown
  );
}

function getConfidenceScore(
  confidence
) {
  return (
    normalizeConfidence(
      confidence
    ) * MAX_SCORE
  );
}

function getRepetitionScore(
  findingCount
) {
  if (
    !Number.isFinite(
      findingCount
    ) ||
    findingCount <= 0
  ) {
    return 0;
  }

  const capped =
    Math.min(
      findingCount,
      MAX_FINDINGS_FOR_REPETITION
    );

  /*
   * Repetition uses diminishing returns.
   *
   * 1 finding  = 0
   * 2 findings = moderate increase
   * 10 findings = maximum repetition contribution
   */
  return (
    Math.log2(capped) /
    Math.log2(
      MAX_FINDINGS_FOR_REPETITION
    )
  ) * MAX_SCORE;
}

function calculateWeightedScore(
  components,
  weights
) {
  const weighted =
    (
      components.severity *
      weights.severity
    ) +
    (
      components.confidence *
      weights.confidence
    ) +
    (
      components.category *
      weights.category
    ) +
    (
      components.repetition *
      weights.repetition
    );

  return clamp(
    weighted,
    0,
    MAX_SCORE
  );
}

function getRiskLevelFromScore(
  score,
  thresholds
) {
  if (
    score >=
    thresholds.critical
  ) {
    return RISK_LEVELS.CRITICAL;
  }

  if (
    score >=
    thresholds.high
  ) {
    return RISK_LEVELS.HIGH;
  }

  if (
    score >=
    thresholds.medium
  ) {
    return RISK_LEVELS.MEDIUM;
  }

  return RISK_LEVELS.LOW;
}

function getHighestSeverity(
  findings
) {
  let highest =
    SEVERITY?.LOW ??
    "low";

  for (
    const finding of findings
  ) {
    const severity =
      normalizeSeverity(
        finding?.severity
      );

    if (
      severityRank(severity) >
      severityRank(highest)
    ) {
      highest = severity;
    }
  }

  return highest;
}

function getHighestCategoryScore(
  findings
) {
  let highest = 0;

  for (
    const finding of findings
  ) {
    highest = Math.max(
      highest,
      getCategoryScore(
        finding?.category
      )
    );
  }

  return highest;
}

function getHighestConfidence(
  findings
) {
  let highest = 0;

  for (
    const finding of findings
  ) {
    highest = Math.max(
      highest,
      normalizeConfidence(
        finding?.confidence
      )
    );
  }

  return highest;
}

function hasCriticalCategory(
  findings
) {
  return findings.some(
    (finding) =>
      CRITICAL_CATEGORIES.has(
        normalizeCategory(
          finding?.category
        )
      )
  );
}

function hasHighRiskCategory(
  findings
) {
  return findings.some(
    (finding) =>
      HIGH_RISK_CATEGORIES.has(
        normalizeCategory(
          finding?.category
        )
      )
  );
}

function hasCriticalSeverity(
  findings
) {
  return findings.some(
    (finding) =>
      normalizeSeverity(
        finding?.severity
      ) ===
      (
        SEVERITY?.CRITICAL ??
        "critical"
      )
  );
}

function hasHighSeverity(
  findings
) {
  return findings.some(
    (finding) =>
      normalizeSeverity(
        finding?.severity
      ) ===
      (
        SEVERITY?.HIGH ??
        "high"
      )
  );
}

function getCriticalFindingCount(
  findings
) {
  return findings.filter(
    (finding) =>
      normalizeSeverity(
        finding?.severity
      ) ===
        (
          SEVERITY?.CRITICAL ??
          "critical"
        ) ||
      CRITICAL_CATEGORIES.has(
        normalizeCategory(
          finding?.category
        )
      )
  ).length;
}

function getHighRiskFindingCount(
  findings
) {
  return findings.filter(
    (finding) =>
      normalizeSeverity(
        finding?.severity
      ) ===
        (
          SEVERITY?.HIGH ??
          "high"
        ) ||
      HIGH_RISK_CATEGORIES.has(
        normalizeCategory(
          finding?.category
        )
      )
  ).length;
}

function createCategorySummary(
  findings
) {
  const summary = {};

  for (
    const finding of findings
  ) {
    const category =
      normalizeCategory(
        finding?.category
      );

    if (
      !summary[category]
    ) {
      summary[category] = {
        count: 0,
        highestSeverity:
          SEVERITY?.LOW ??
          "low",
        highestConfidence: 0,
        highestScore: 0,
      };
    }

    const item =
      summary[category];

    item.count += 1;

    const severity =
      normalizeSeverity(
        finding?.severity
      );

    if (
      severityRank(severity) >
      severityRank(
        item.highestSeverity
      )
    ) {
      item.highestSeverity =
        severity;
    }

    item.highestConfidence =
      Math.max(
        item.highestConfidence,
        normalizeConfidence(
          finding?.confidence
        )
      );

    item.highestScore =
      Math.max(
        item.highestScore,
        getCategoryScore(
          category
        )
      );
  }

  return summary;
}

function createSeveritySummary(
  findings
) {
  const summary = {
    low: 0,
    medium: 0,
    high: 0,
    critical: 0,
  };

  for (
    const finding of findings
  ) {
    const severity =
      normalizeSeverity(
        finding?.severity
      );

    if (
      Object.prototype.hasOwnProperty.call(
        summary,
        severity
      )
    ) {
      summary[severity] += 1;
    }
  }

  return summary;
}

function createConfidenceBuckets(
  findings
) {
  const buckets = {
    low: 0,
    medium: 0,
    high: 0,
    veryHigh: 0,
  };

  for (
    const finding of findings
  ) {
    const confidence =
      normalizeConfidence(
        finding?.confidence
      );

    if (
      confidence >= 0.9
    ) {
      buckets.veryHigh += 1;
    } else if (
      confidence >= 0.75
    ) {
      buckets.high += 1;
    } else if (
      confidence >= 0.5
    ) {
      buckets.medium += 1;
    } else {
      buckets.low += 1;
    }
  }

  return buckets;
}

function normalizeFinding(
  finding
) {
  if (
    !isObject(finding)
  ) {
    return null;
  }

  return {
    ruleId:
      typeof finding.ruleId ===
      "string"
        ? finding.ruleId
        : null,

    category:
      normalizeCategory(
        finding.category
      ),

    severity:
      normalizeSeverity(
        finding.severity
      ),

    confidence:
      normalizeConfidence(
        finding.confidence
      ),

    priority:
      Number.isFinite(
        finding.priority
      )
        ? finding.priority
        : 0,
  };
}

function normalizeFindings(
  findings
) {
  if (
    !Array.isArray(findings)
  ) {
    return [];
  }

  return findings
    .map(
      normalizeFinding
    )
    .filter(Boolean);
}

function calculateFindingScore(
  finding,
  findingCount,
  weights
) {
  const severity =
    getSeverityScore(
      finding.severity
    );

  const confidence =
    getConfidenceScore(
      finding.confidence
    );

  const category =
    getCategoryScore(
      finding.category
    );

  const repetition =
    getRepetitionScore(
      findingCount
    );

  const score =
    calculateWeightedScore(
      {
        severity,
        confidence,
        category,
        repetition,
      },
      weights
    );

  return {
    score,
    components: {
      severity,
      confidence,
      category,
      repetition,
    },
  };
}

function applyRiskFloor(
  score,
  findings
) {
  let result = score;

  /*
   * Critical categories should never produce a LOW
   * aggregate score merely because confidence is low.
   *
   * The matcher should normally provide confidence,
   * but this floor protects against configuration mistakes.
   */
  if (
    hasCriticalCategory(
      findings
    ) ||
    hasCriticalSeverity(
      findings
    )
  ) {
    result = Math.max(
      result,
      85
    );
  } else if (
    hasHighRiskCategory(
      findings
    ) ||
    hasHighSeverity(
      findings
    )
  ) {
    result = Math.max(
      result,
      60
    );
  }

  return clamp(
    result,
    0,
    MAX_SCORE
  );
}

function applyConfidenceGuard(
  score,
  findings
) {
  if (
    findings.length === 0
  ) {
    return 0;
  }

  const highestConfidence =
    getHighestConfidence(
      findings
    );

  /*
   * A very low-confidence finding should not independently
   * create a critical aggregate score unless its category or
   * severity explicitly indicates critical risk.
   */
  if (
    highestConfidence < 0.4 &&
    !hasCriticalCategory(
      findings
    ) &&
    !hasCriticalSeverity(
      findings
    )
  ) {
    return Math.min(
      score,
      59
    );
  }

  return score;
}

function calculateAggregateScore(
  findings,
  weights
) {
  if (
    findings.length === 0
  ) {
    return {
      score: 0,
      averageFindingScore: 0,
      maximumFindingScore: 0,
      components: {
        severity: 0,
        confidence: 0,
        category: 0,
        repetition: 0,
      },
    };
  }

  const findingScores =
    findings.map(
      (finding) =>
        calculateFindingScore(
          finding,
          findings.length,
          weights
        )
    );

  const maximumFindingScore =
    findingScores.reduce(
      (maximum, item) =>
        Math.max(
          maximum,
          item.score
        ),
      0
    );

  const averageFindingScore =
    findingScores.reduce(
      (sum, item) =>
        sum + item.score,
      0
    ) /
    findingScores.length;

  /*
   * Highest finding receives the strongest influence.
   * Additional findings contribute through the average.
   */
  let score =
    (
      maximumFindingScore *
      0.70
    ) +
    (
      averageFindingScore *
      0.30
    );

  const componentTotals =
    findingScores.reduce(
      (totals, item) => {
        totals.severity +=
          item.components.severity;

        totals.confidence +=
          item.components.confidence;

        totals.category +=
          item.components.category;

        totals.repetition +=
          item.components.repetition;

        return totals;
      },
      {
        severity: 0,
        confidence: 0,
        category: 0,
        repetition: 0,
      }
    );

  const divisor =
    findingScores.length;

  const components = {
    severity:
      componentTotals.severity /
      divisor,

    confidence:
      componentTotals.confidence /
      divisor,

    category:
      componentTotals.category /
      divisor,

    repetition:
      componentTotals.repetition /
      divisor,
  };

  score =
    applyRiskFloor(
      score,
      findings
    );

  score =
    applyConfidenceGuard(
      score,
      findings
    );

  return {
    score: clamp(
      score,
      0,
      MAX_SCORE
    ),

    averageFindingScore,

    maximumFindingScore,

    components,
  };
}

function calculateRiskDelta(
  previousScore,
  currentScore
) {
  if (
    !Number.isFinite(
      previousScore
    )
  ) {
    return 0;
  }

  return (
    currentScore -
    previousScore
  );
}

function getRiskLabel(
  level
) {
  switch (level) {
    case RISK_LEVELS.CRITICAL:
      return "Critical";

    case RISK_LEVELS.HIGH:
      return "High";

    case RISK_LEVELS.MEDIUM:
      return "Medium";

    default:
      return "Low";
  }
}

function getRiskDescription(
  level
) {
  switch (level) {
    case RISK_LEVELS.CRITICAL:
      return (
        "Highly sensitive information was detected."
      );

    case RISK_LEVELS.HIGH:
      return (
        "High-risk sensitive information was detected."
      );

    case RISK_LEVELS.MEDIUM:
      return (
        "Potentially sensitive information was detected."
      );

    default:
      return (
        "No significant sensitive-data risk was detected."
      );
  }
}

function createRiskFactors(
  findings
) {
  const factors = [];

  if (
    hasCriticalCategory(
      findings
    )
  ) {
    factors.push(
      "critical_category"
    );
  }

  if (
    hasCriticalSeverity(
      findings
    )
  ) {
    factors.push(
      "critical_severity"
    );
  }

  if (
    hasHighRiskCategory(
      findings
    )
  ) {
    factors.push(
      "high_risk_category"
    );
  }

  if (
    hasHighSeverity(
      findings
    )
  ) {
    factors.push(
      "high_severity"
    );
  }

  if (
    findings.length >= 3
  ) {
    factors.push(
      "multiple_findings"
    );
  }

  if (
    findings.length >=
    MAX_FINDINGS_FOR_REPETITION
  ) {
    factors.push(
      "high_finding_volume"
    );
  }

  return factors;
}

function createSafeFindingDetails(
  findings
) {
  /*
   * Deliberately excludes:
   * - matchedText
   * - original prompt
   * - normalized prompt
   * - regex groups
   * - clipboard data
   * - file contents
   */
  return findings.map(
    (finding) => ({
      ruleId:
        finding.ruleId,

      category:
        finding.category,

      severity:
        finding.severity,

      confidence:
        finding.confidence,

      priority:
        finding.priority,
    })
  );
}

/**
 * Calculate risk from matcher findings.
 *
 * @param {Array<object>} findings
 * @param {object} options
 * @returns {object}
 */
export function calculateRiskScore(
  findings,
  options = {}
) {
  const startedAt =
    typeof performance !==
      "undefined" &&
    typeof performance.now ===
      "function"
      ? performance.now()
      : Date.now();

  const normalizedFindings =
    normalizeFindings(
      findings
    );

  const thresholds =
    normalizeThresholds(
      options.thresholds
    );

  const weights =
    normalizeWeights(
      options.weights
    );

  const aggregate =
    calculateAggregateScore(
      normalizedFindings,
      weights
    );

  let score =
    Math.round(
      aggregate.score
    );

  score = clamp(
    score,
    0,
    MAX_SCORE
  );

  const riskLevel =
    getRiskLevelFromScore(
      score,
      thresholds
    );

  const highestSeverity =
    getHighestSeverity(
      normalizedFindings
    );

  const highestCategoryScore =
    getHighestCategoryScore(
      normalizedFindings
    );

  const highestConfidence =
    getHighestConfidence(
      normalizedFindings
    );

  const result = {
    version:
      RISK_SCORE_VERSION,

    score,

    level:
      riskLevel,

    label:
      getRiskLabel(
        riskLevel
      ),

    description:
      getRiskDescription(
        riskLevel
      ),

    findingCount:
      normalizedFindings.length,

    highestSeverity,

    highestConfidence,

    highestCategoryScore,

    criticalFindingCount:
      getCriticalFindingCount(
        normalizedFindings
      ),

    highRiskFindingCount:
      getHighRiskFindingCount(
        normalizedFindings
      ),

    hasCriticalRisk:
      hasCriticalCategory(
        normalizedFindings
      ) ||
      hasCriticalSeverity(
        normalizedFindings
      ),

    hasHighRisk:
      hasHighRiskCategory(
        normalizedFindings
      ) ||
      hasHighSeverity(
        normalizedFindings
      ),

    factors:
      createRiskFactors(
        normalizedFindings
      ),

    components:
      aggregate.components,

    averageFindingScore:
      aggregate.averageFindingScore,

    maximumFindingScore:
      aggregate.maximumFindingScore,

    categorySummary:
      createCategorySummary(
        normalizedFindings
      ),

    severitySummary:
      createSeveritySummary(
        normalizedFindings
      ),

    confidenceBuckets:
      createConfidenceBuckets(
        normalizedFindings
      ),

    thresholds,

    weights,

    durationMs:
      (
        typeof performance !==
          "undefined" &&
        typeof performance.now ===
          "function"
          ? performance.now()
          : Date.now()
      ) - startedAt,
  };

  if (
    options.includeFindingDetails ===
    true
  ) {
    result.findings =
      createSafeFindingDetails(
        normalizedFindings
      );
  }

  if (
    Number.isFinite(
      options.previousScore
    )
  ) {
    result.previousScore =
      clamp(
        options.previousScore,
        0,
        MAX_SCORE
      );

    result.scoreDelta =
      calculateRiskDelta(
        result.previousScore,
        result.score
      );
  }

  return result;
}

/**
 * Calculate risk directly from a matcher result.
 *
 * @param {object} matcherResult
 * @param {object} options
 * @returns {object}
 */
export function calculateRiskFromMatcherResult(
  matcherResult,
  options = {}
) {
  if (
    !isObject(
      matcherResult
    )
  ) {
    return calculateRiskScore(
      [],
      options
    );
  }

  const result =
    calculateRiskScore(
      Array.isArray(
        matcherResult.findings
      )
        ? matcherResult.findings
        : [],
      options
    );

  return {
    ...result,

    matcher: {
      matched:
        matcherResult.matched ===
        true,

      findingCount:
        Number.isFinite(
          matcherResult.findingCount
        )
          ? matcherResult.findingCount
          : 0,

      ruleCount:
        Number.isFinite(
          matcherResult.ruleCount
        )
          ? matcherResult.ruleCount
          : 0,

      rulesMatched:
        Number.isFinite(
          matcherResult.rulesMatched
        )
          ? matcherResult.rulesMatched
          : 0,

      truncated:
        matcherResult.truncated ===
        true,
    },
  };
}

/**
 * Return a simple risk level for a score.
 *
 * @param {number} score
 * @param {object} thresholds
 * @returns {string}
 */
export function getRiskLevel(
  score,
  thresholds = DEFAULT_RISK_THRESHOLDS
) {
  const normalizedThresholds =
    normalizeThresholds(
      thresholds
    );

  const normalizedScore =
    clamp(
      score,
      0,
      MAX_SCORE
    );

  return getRiskLevelFromScore(
    normalizedScore,
    normalizedThresholds
  );
}

/**
 * Return a numeric risk rank.
 *
 * @param {string} level
 * @returns {number}
 */
export function getRiskRank(
  level
) {
  return riskRank(
    typeof level === "string"
      ? level
      : ""
  );
}

/**
 * Compare two risk levels.
 *
 * @param {string} first
 * @param {string} second
 * @returns {number}
 */
export function compareRiskLevels(
  first,
  second
) {
  return (
    riskRank(first) -
    riskRank(second)
  );
}

/**
 * Return true if the first risk level is
 * greater than or equal to the second.
 *
 * @param {string} first
 * @param {string} second
 * @returns {boolean}
 */
export function isRiskAtLeast(
  first,
  second
) {
  return (
    riskRank(first) >=
    riskRank(second)
  );
}

/**
 * Return true if the risk is high or critical.
 *
 * @param {string} level
 * @returns {boolean}
 */
export function isHighRisk(
  level
) {
  return (
    riskRank(level) >=
    riskRank(
      RISK_LEVELS.HIGH
    )
  );
}

/**
 * Return true if the risk is critical.
 *
 * @param {string} level
 * @returns {boolean}
 */
export function isCriticalRisk(
  level
) {
  return (
    riskRank(level) >=
    riskRank(
      RISK_LEVELS.CRITICAL
    )
  );
}

/**
 * Return severity score for a finding.
 *
 * @param {string} severity
 * @returns {number}
 */
export function getSeverityScore(
  severity
) {
  return getSeverityScoreInternal(
    severity
  );
}

function getSeverityScoreInternal(
  severity
) {
  return getSeverityScore(
    severity
  );
}

/**
 * Return category score.
 *
 * @param {string} category
 * @returns {number}
 */
export function getCategoryScore(
  category
) {
  return (
    CATEGORY_SCORES[
      normalizeCategory(
        category
      )
    ] ??
    CATEGORY_SCORES.unknown
  );
}

/**
 * Return confidence score from 0-1 confidence.
 *
 * @param {number} confidence
 * @returns {number}
 */
export function getConfidenceScore(
  confidence
) {
  return (
    normalizeConfidence(
      confidence
    ) * MAX_SCORE
  );
}

/**
 * Return normalized risk thresholds.
 *
 * @param {object} thresholds
 * @returns {object}
 */
export function getRiskThresholds(
  thresholds = {}
) {
  return normalizeThresholds(
    thresholds
  );
}

/**
 * Return normalized risk weights.
 *
 * @param {object} weights
 * @returns {object}
 */
export function getRiskWeights(
  weights = {}
) {
  return normalizeWeights(
    weights
  );
}

/**
 * Return a safe risk summary.
 *
 * No sensitive matched content is returned.
 *
 * @param {object} riskResult
 * @returns {object}
 */
export function getRiskSummary(
  riskResult
) {
  if (
    !isObject(
      riskResult
    )
  ) {
    return {
      score: 0,
      level: RISK_LEVELS.LOW,
      findingCount: 0,
      highestSeverity:
        SEVERITY?.LOW ??
        "low",
      hasCriticalRisk: false,
      hasHighRisk: false,
    };
  }

  return {
    score:
      Number.isFinite(
        riskResult.score
      )
        ? riskResult.score
        : 0,

    level:
      typeof riskResult.level ===
      "string"
        ? riskResult.level
        : RISK_LEVELS.LOW,

    label:
      typeof riskResult.label ===
      "string"
        ? riskResult.label
        : getRiskLabel(
            riskResult.level
          ),

    findingCount:
      Number.isFinite(
        riskResult.findingCount
      )
        ? riskResult.findingCount
        : 0,

    highestSeverity:
      normalizeSeverity(
        riskResult.highestSeverity
      ),

    highestConfidence:
      normalizeConfidence(
        riskResult.highestConfidence
      ),

    criticalFindingCount:
      Number.isFinite(
        riskResult.criticalFindingCount
      )
        ? riskResult.criticalFindingCount
        : 0,

    highRiskFindingCount:
      Number.isFinite(
        riskResult.highRiskFindingCount
      )
        ? riskResult.highRiskFindingCount
        : 0,

    hasCriticalRisk:
      riskResult.hasCriticalRisk ===
      true,

    hasHighRisk:
      riskResult.hasHighRisk ===
      true,
  };
}

/**
 * Return risk engine diagnostics.
 *
 * This contains no user data.
 *
 * @returns {object}
 */
export function getRiskScoreDiagnostics() {
  return {
    version:
      RISK_SCORE_VERSION,

    maxScore:
      MAX_SCORE,

    levels: {
      ...RISK_LEVELS,
    },

    thresholds: {
      ...DEFAULT_RISK_THRESHOLDS,
    },

    defaultWeights: {
      ...DEFAULT_WEIGHTS,
    },

    severityScores: {
      ...SEVERITY_SCORES,
    },

    categoryScores: {
      ...CATEGORY_SCORES,
    },
  };
}

/**
 * Validate custom risk configuration.
 *
 * @param {object} config
 * @returns {{valid:boolean,errors:string[]}}
 */
export function validateRiskConfiguration(
  config = {}
) {
  const errors = [];

  if (
    !isObject(config)
  ) {
    return {
      valid: false,
      errors: [
        "Risk configuration must be an object.",
      ],
    };
  }

  if (
    config.thresholds !==
      undefined
  ) {
    if (
      !isObject(
        config.thresholds
      )
    ) {
      errors.push(
        "Risk thresholds must be an object."
      );
    } else {
      for (
        const key of [
          "low",
          "medium",
          "high",
          "critical",
        ]
      ) {
        if (
          config.thresholds[key] !==
            undefined &&
          !isFiniteNumber(
            config.thresholds[key]
          )
        ) {
          errors.push(
            `Risk threshold "${key}" must be numeric.`
          );
        }
      }
    }
  }

  if (
    config.weights !==
      undefined
  ) {
    if (
      !isObject(
        config.weights
      )
    ) {
      errors.push(
        "Risk weights must be an object."
      );
    } else {
      for (
        const key of [
          "severity",
          "confidence",
          "category",
          "repetition",
        ]
      ) {
        if (
          config.weights[key] !==
            undefined &&
          (
            !isFiniteNumber(
              config.weights[key]
            ) ||
            config.weights[key] < 0
          )
        ) {
          errors.push(
            `Risk weight "${key}" must be a non-negative number.`
          );
        }
      }
    }
  }

  return {
    valid:
      errors.length === 0,
    errors,
  };
}

/**
 * Constants exported for scanner and tests.
 */
export {
  RISK_SCORE_VERSION,
  RISK_LEVELS,
  DEFAULT_RISK_THRESHOLDS,
  DEFAULT_WEIGHTS,
  SEVERITY_SCORES,
  CATEGORY_SCORES,
  CRITICAL_CATEGORIES,
  HIGH_RISK_CATEGORIES,
};
