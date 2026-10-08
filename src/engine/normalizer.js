/**
 * SanitizerPro
 * Local text normalization engine.
 *
 * Responsibilities:
 * - Normalize Unicode safely for local detection.
 * - Remove invisible characters commonly used to evade detection.
 * - Normalize line endings and whitespace.
 * - Normalize common Unicode punctuation.
 * - Provide case-insensitive matching views.
 * - Provide compact matching views for values such as:
 *   credit cards, IBANs, phone numbers, tokens, and identifiers.
 * - Preserve a mapping between normalized text and original text.
 * - Never persist, transmit, or log sensitive content.
 *
 * This module intentionally does not:
 * - scan for secrets
 * - decide policy
 * - mask content
 * - access Chrome APIs
 * - access the DOM
 * - access the clipboard
 * - perform network requests
 */

import { SCAN_LIMITS } from "../config/defaults.js";

const DEFAULT_MAX_INPUT_LENGTH =
  Number.isInteger(SCAN_LIMITS?.maxTextCharacters) &&
  SCAN_LIMITS.maxTextCharacters > 0
    ? SCAN_LIMITS.maxTextCharacters
    : 250000;

const DEFAULT_MAX_NORMALIZED_LENGTH =
  Number.isInteger(SCAN_LIMITS?.maxNormalizedTextCharacters) &&
  SCAN_LIMITS.maxNormalizedTextCharacters > 0
    ? SCAN_LIMITS.maxNormalizedTextCharacters
    : DEFAULT_MAX_INPUT_LENGTH;

const NORMALIZATION_VERSION = 1;

const ZERO_WIDTH_CODE_POINTS = new Set([
  0x00ad, // soft hyphen
  0x061c, // Arabic letter mark
  0x180e, // Mongolian vowel separator
  0x200b, // zero width space
  0x200c, // zero width non-joiner
  0x200d, // zero width joiner
  0x200e, // left-to-right mark
  0x200f, // right-to-left mark
  0x202a, // left-to-right embedding
  0x202b, // right-to-left embedding
  0x202c, // pop directional formatting
  0x202d, // left-to-right override
  0x202e, // right-to-left override
  0x2060, // word joiner
  0x2061, // function application
  0x2062, // invisible times
  0x2063, // invisible separator
  0x2064, // invisible plus
  0x2066, // left-to-right isolate
  0x2067, // right-to-left isolate
  0x2068, // first strong isolate
  0x2069, // pop directional isolate
  0xfeff, // zero width no-break space / BOM
]);

const CONTROL_CODE_POINTS_TO_REMOVE = new Set([
  0x0000,
  0x0001,
  0x0002,
  0x0003,
  0x0004,
  0x0005,
  0x0006,
  0x0007,
  0x0008,
  0x000b,
  0x000c,
  0x000e,
  0x000f,
  0x0010,
  0x0011,
  0x0012,
  0x0013,
  0x0014,
  0x0015,
  0x0016,
  0x0017,
  0x0018,
  0x0019,
  0x001a,
  0x001b,
  0x001c,
  0x001d,
  0x001e,
  0x001f,
  0x007f,
  0x0080,
  0x0081,
  0x0082,
  0x0083,
  0x0084,
  0x0085,
  0x0086,
  0x0087,
  0x0088,
  0x0089,
  0x008a,
  0x008b,
  0x008c,
  0x008d,
  0x008e,
  0x008f,
  0x0090,
  0x0091,
  0x0092,
  0x0093,
  0x0094,
  0x0095,
  0x0096,
  0x0097,
  0x0098,
  0x0099,
  0x009a,
  0x009b,
  0x009c,
  0x009d,
  0x009e,
  0x009f,
]);

const NORMALIZED_WHITESPACE = " ";

const PUNCTUATION_REPLACEMENTS = new Map([
  ["\u2018", "'"],
  ["\u2019", "'"],
  ["\u201A", "'"],
  ["\u201B", "'"],
  ["\u2032", "'"],
  ["\u2035", "'"],

  ["\u201C", '"'],
  ["\u201D", '"'],
  ["\u201E", '"'],
  ["\u201F", '"'],
  ["\u2033", '"'],
  ["\u2036", '"'],

  ["\u2010", "-"],
  ["\u2011", "-"],
  ["\u2012", "-"],
  ["\u2013", "-"],
  ["\u2014", "-"],
  ["\u2015", "-"],
  ["\u2212", "-"],

  ["\u2026", "..."],

  ["\u00a0", " "],
  ["\u2007", " "],
  ["\u202f", " "],

  ["\u2044", "/"],
  ["\u2215", "/"],
]);

const COMPACT_SEPARATOR_PATTERN = /[\s\-_.:/\\()[\]{}'",`~|]+/gu;

const DEFAULT_OPTIONS = Object.freeze({
  unicodeNormalization: "NFKC",
  removeInvisibleCharacters: true,
  removeControlCharacters: true,
  normalizePunctuation: true,
  normalizeWhitespace: true,
  collapseWhitespace: true,
  trimWhitespace: true,
  createLowercaseView: true,
  createCompactView: true,
  compactSeparators: true,
  maxInputCharacters: DEFAULT_MAX_INPUT_LENGTH,
  maxNormalizedCharacters: DEFAULT_MAX_NORMALIZED_LENGTH,
});

function isObject(value) {
  return value !== null && typeof value === "object";
}

function isValidString(value) {
  return typeof value === "string";
}

function toSafeInteger(value, fallback, minimum = 0) {
  if (!Number.isFinite(value)) {
    return fallback;
  }

  const integer = Math.floor(value);

  if (integer < minimum) {
    return fallback;
  }

  return integer;
}

function clampStringLength(value, maximum) {
  if (value.length <= maximum) {
    return {
      value,
      truncated: false,
    };
  }

  return {
    value: value.slice(0, maximum),
    truncated: true,
  };
}

function getCodePointSize(character) {
  return character.length;
}

function isWhitespaceCodePoint(codePoint) {
  return /\s/u.test(String.fromCodePoint(codePoint));
}

function isZeroWidthCodePoint(codePoint) {
  return ZERO_WIDTH_CODE_POINTS.has(codePoint);
}

function isControlCodePoint(codePoint) {
  return CONTROL_CODE_POINTS_TO_REMOVE.has(codePoint);
}

function normalizeLineBreak(character) {
  if (character === "\r" || character === "\n") {
    return "\n";
  }

  return character;
}

function normalizePunctuationCharacter(character) {
  return PUNCTUATION_REPLACEMENTS.get(character) ?? character;
}

function normalizeCharacter(character, options) {
  let value = character;

  if (options.unicodeNormalization) {
    try {
      value = value.normalize(options.unicodeNormalization);
    } catch {
      value = character;
    }
  }

  if (options.normalizePunctuation) {
    value = Array.from(value, normalizePunctuationCharacter).join("");
  }

  return value;
}

function appendMappedText(output, mappings, text, originalStart, originalEnd) {
  if (!text) {
    return;
  }

  const outputStart = output.length;

  output.push(text);

  const outputEnd = output.length;

  mappings.push({
    normalizedStart: outputStart,
    normalizedEnd: outputEnd,
    originalStart,
    originalEnd,
  });
}

function mergeMappingSegments(segments) {
  if (segments.length <= 1) {
    return segments.slice();
  }

  const merged = [];

  for (const segment of segments) {
    if (!segment) {
      continue;
    }

    const previous = merged[merged.length - 1];

    if (
      previous &&
      previous.normalizedEnd === segment.normalizedStart &&
      previous.originalEnd === segment.originalStart
    ) {
      previous.normalizedEnd = segment.normalizedEnd;
      previous.originalEnd = segment.originalEnd;
      continue;
    }

    merged.push({
      normalizedStart: segment.normalizedStart,
      normalizedEnd: segment.normalizedEnd,
      originalStart: segment.originalStart,
      originalEnd: segment.originalEnd,
    });
  }

  return merged;
}

function createSegment(
  normalizedStart,
  normalizedEnd,
  originalStart,
  originalEnd
) {
  return {
    normalizedStart,
    normalizedEnd,
    originalStart,
    originalEnd,
  };
}

function appendWhitespace(
  output,
  mappings,
  originalStart,
  originalEnd,
  state
) {
  if (!state.lastWasWhitespace) {
    const start = output.length;

    output.push(NORMALIZED_WHITESPACE);

    mappings.push(
      createSegment(
        start,
        start + 1,
        originalStart,
        originalEnd
      )
    );

    state.lastWasWhitespace = true;
    return;
  }

  const previous = mappings[mappings.length - 1];

  if (previous) {
    previous.originalEnd = originalEnd;
  }
}

function removeTrailingWhitespace(output, mappings) {
  if (output.length === 0) {
    return;
  }

  while (
    output.length > 0 &&
    output[output.length - 1] === NORMALIZED_WHITESPACE
  ) {
    output.pop();

    const last = mappings[mappings.length - 1];

    if (!last) {
      continue;
    }

    if (last.normalizedEnd > output.length) {
      last.normalizedEnd = output.length;
    }

    if (last.normalizedStart >= last.normalizedEnd) {
      mappings.pop();
    }
  }
}

function normalizeInputCharacters(input, options) {
  const output = [];
  const mappings = [];

  let originalIndex = 0;
  let lastWasWhitespace = false;

  for (const character of input) {
    const originalStart = originalIndex;
    const originalEnd = originalIndex + getCodePointSize(character);

    originalIndex = originalEnd;

    const codePoint = character.codePointAt(0);

    if (
      options.removeInvisibleCharacters &&
      isZeroWidthCodePoint(codePoint)
    ) {
      continue;
    }

    if (
      options.removeControlCharacters &&
      isControlCodePoint(codePoint)
    ) {
      continue;
    }

    let normalizedCharacter = normalizeLineBreak(character);

    if (options.normalizeWhitespace) {
      if (isWhitespaceCodePoint(codePoint)) {
        if (options.collapseWhitespace) {
          appendWhitespace(
            output,
            mappings,
            originalStart,
            originalEnd,
            {
              get lastWasWhitespace() {
                return lastWasWhitespace;
              },
              set lastWasWhitespace(value) {
                lastWasWhitespace = value;
              },
            }
          );

          continue;
        }

        normalizedCharacter = NORMALIZED_WHITESPACE;
      }
    }

    normalizedCharacter = normalizeCharacter(
      normalizedCharacter,
      options
    );

    if (!normalizedCharacter) {
      continue;
    }

    if (
      options.normalizeWhitespace &&
      options.collapseWhitespace &&
      normalizedCharacter.length === 1 &&
      isWhitespaceCodePoint(normalizedCharacter.codePointAt(0))
    ) {
      appendWhitespace(
        output,
        mappings,
        originalStart,
        originalEnd,
        {
          get lastWasWhitespace() {
            return lastWasWhitespace;
          },
          set lastWasWhitespace(value) {
            lastWasWhitespace = value;
          },
        }
      );

      continue;
    }

    const outputStart = output.length;

    output.push(normalizedCharacter);

    const outputEnd = output.length;

    mappings.push(
      createSegment(
        outputStart,
        outputEnd,
        originalStart,
        originalEnd
      )
    );

    lastWasWhitespace = false;
  }

  if (options.trimWhitespace) {
    removeTrailingWhitespace(output, mappings);

    if (output.length > 0 && output[0] === NORMALIZED_WHITESPACE) {
      output.shift();

      for (const segment of mappings) {
        segment.normalizedStart -= 1;
        segment.normalizedEnd -= 1;
      }

      while (mappings.length > 0 && mappings[0].normalizedEnd <= 0) {
        mappings.shift();
      }

      if (mappings.length > 0 && mappings[0].normalizedStart < 0) {
        mappings[0].normalizedStart = 0;
      }
    }
  }

  return {
    text: output.join(""),
    mappings: mergeMappingSegments(mappings),
  };
}

function buildLowercaseView(normalizedText) {
  if (!normalizedText) {
    return "";
  }

  try {
    return normalizedText.toLocaleLowerCase("en-US");
  } catch {
    return normalizedText.toLowerCase();
  }
}

function isCompactSeparator(character) {
  return COMPACT_SEPARATOR_PATTERN.test(character);
}

function buildCompactView(normalizedText, normalizedMappings) {
  if (!normalizedText) {
    return {
      text: "",
      mappings: [],
    };
  }

  const compactOutput = [];
  const compactMappings = [];

  let normalizedIndex = 0;

  for (const character of normalizedText) {
    const width = character.length;
    const normalizedStart = normalizedIndex;
    const normalizedEnd = normalizedIndex + width;

    normalizedIndex = normalizedEnd;

    if (isCompactSeparator(character)) {
      continue;
    }

    const originalRange = mapNormalizedRangeToOriginal(
      normalizedMappings,
      normalizedStart,
      normalizedEnd
    );

    if (!originalRange) {
      continue;
    }

    const compactStart = compactOutput.length;

    compactOutput.push(character);

    const compactEnd = compactOutput.length;

    compactMappings.push(
      createSegment(
        compactStart,
        compactEnd,
        originalRange.start,
        originalRange.end
      )
    );
  }

  return {
    text: compactOutput.join(""),
    mappings: mergeMappingSegments(compactMappings),
  };
}

function normalizeOptions(options = {}) {
  const input = isObject(options) ? options : {};

  return {
    unicodeNormalization:
      typeof input.unicodeNormalization === "string"
        ? input.unicodeNormalization
        : DEFAULT_OPTIONS.unicodeNormalization,

    removeInvisibleCharacters:
      input.removeInvisibleCharacters !== false,

    removeControlCharacters:
      input.removeControlCharacters !== false,

    normalizePunctuation:
      input.normalizePunctuation !== false,

    normalizeWhitespace:
      input.normalizeWhitespace !== false,

    collapseWhitespace:
      input.collapseWhitespace !== false,

    trimWhitespace:
      input.trimWhitespace !== false,

    createLowercaseView:
      input.createLowercaseView !== false,

    createCompactView:
      input.createCompactView !== false,

    compactSeparators:
      input.compactSeparators !== false,

    maxInputCharacters: toSafeInteger(
      input.maxInputCharacters,
      DEFAULT_OPTIONS.maxInputCharacters,
      1
    ),

    maxNormalizedCharacters: toSafeInteger(
      input.maxNormalizedCharacters,
      DEFAULT_OPTIONS.maxNormalizedCharacters,
      1
    ),
  };
}

function normalizeRange(start, end, length) {
  const safeStart = Math.max(
    0,
    Math.min(length, Math.floor(Number(start) || 0))
  );

  const safeEnd = Math.max(
    safeStart,
    Math.min(length, Math.floor(Number(end) || 0))
  );

  return {
    start: safeStart,
    end: safeEnd,
  };
}

function findMappingSegment(mappings, index) {
  if (!Array.isArray(mappings) || mappings.length === 0) {
    return null;
  }

  let low = 0;
  let high = mappings.length - 1;

  while (low <= high) {
    const middle = (low + high) >> 1;
    const segment = mappings[middle];

    if (index < segment.normalizedStart) {
      high = middle - 1;
      continue;
    }

    if (index >= segment.normalizedEnd) {
      low = middle + 1;
      continue;
    }

    return segment;
  }

  return null;
}

function mapNormalizedRangeToOriginal(mappings, start, end) {
  if (!Array.isArray(mappings) || mappings.length === 0) {
    return null;
  }

  if (end <= start) {
    return null;
  }

  const first = findMappingSegment(mappings, start);
  const last = findMappingSegment(mappings, Math.max(start, end - 1));

  if (!first || !last) {
    return null;
  }

  return {
    start: first.originalStart,
    end: last.originalEnd,
  };
}

function mapOriginalRangeToNormalized(mappings, start, end) {
  if (!Array.isArray(mappings) || mappings.length === 0) {
    return null;
  }

  if (end <= start) {
    return null;
  }

  let normalizedStart = null;
  let normalizedEnd = null;

  for (const segment of mappings) {
    if (segment.originalEnd <= start) {
      continue;
    }

    if (segment.originalStart >= end) {
      break;
    }

    if (normalizedStart === null) {
      normalizedStart = segment.normalizedStart;
    }

    normalizedEnd = segment.normalizedEnd;
  }

  if (normalizedStart === null || normalizedEnd === null) {
    return null;
  }

  return {
    start: normalizedStart,
    end: normalizedEnd,
  };
}

function sliceOriginalByNormalizedRange(
  originalText,
  mappings,
  start,
  end
) {
  if (typeof originalText !== "string") {
    return "";
  }

  const range = mapNormalizedRangeToOriginal(
    mappings,
    start,
    end
  );

  if (!range) {
    return "";
  }

  return originalText.slice(range.start, range.end);
}

function createNormalizationStats(
  originalText,
  normalizedText,
  compactText,
  truncated
) {
  const originalLength =
    typeof originalText === "string"
      ? originalText.length
      : 0;

  return {
    originalLength,
    normalizedLength: normalizedText.length,
    compactLength: compactText.length,
    charactersRemoved:
      Math.max(0, originalLength - normalizedText.length),
    compressionRatio:
      originalLength > 0
        ? normalizedText.length / originalLength
        : 1,
    truncated,
    changed: originalText !== normalizedText,
  };
}

/**
 * Normalize arbitrary text into deterministic matching views.
 *
 * @param {string} input
 * @param {object} options
 * @returns {object}
 */
export function normalizeText(input, options = {}) {
  const normalizedOptions = normalizeOptions(options);

  if (typeof input !== "string") {
    return createEmptyNormalizationResult(
      input,
      normalizedOptions
    );
  }

  const inputLimit = clampStringLength(
    input,
    normalizedOptions.maxInputCharacters
  );

  const sourceText = inputLimit.value;

  const normalized = normalizeInputCharacters(
    sourceText,
    normalizedOptions
  );

  let normalizedText = normalized.text;
  let mappings = normalized.mappings;

  let truncatedNormalized = false;

  if (
    normalizedText.length >
    normalizedOptions.maxNormalizedCharacters
  ) {
    const limited = clampStringLength(
      normalizedText,
      normalizedOptions.maxNormalizedCharacters
    );

    normalizedText = limited.value;
    truncatedNormalized = limited.truncated;

    const validEnd = normalizedText.length;

    mappings = mappings
      .filter(
        (segment) => segment.normalizedStart < validEnd
      )
      .map((segment) => ({
        normalizedStart: segment.normalizedStart,
        normalizedEnd: Math.min(
          segment.normalizedEnd,
          validEnd
        ),
        originalStart: segment.originalStart,
        originalEnd: segment.originalEnd,
      }))
      .filter(
        (segment) =>
          segment.normalizedStart <
          segment.normalizedEnd
      );
  }

  const lowercaseText = normalizedOptions.createLowercaseView
    ? buildLowercaseView(normalizedText)
    : "";

  const compact = normalizedOptions.createCompactView &&
    normalizedOptions.compactSeparators
    ? buildCompactView(normalizedText, mappings)
    : {
        text: "",
        mappings: [],
      };

  const compactText = compact.text;

  return {
    version: NORMALIZATION_VERSION,

    originalText: sourceText,

    normalizedText,

    lowercaseText,

    compactText,

    mappings,

    compactMappings: compact.mappings,

    truncated:
      inputLimit.truncated ||
      truncatedNormalized,

    stats: createNormalizationStats(
      input,
      normalizedText,
      compactText,
      inputLimit.truncated || truncatedNormalized
    ),

    options: {
      unicodeNormalization:
        normalizedOptions.unicodeNormalization,

      removeInvisibleCharacters:
        normalizedOptions.removeInvisibleCharacters,

      removeControlCharacters:
        normalizedOptions.removeControlCharacters,

      normalizePunctuation:
        normalizedOptions.normalizePunctuation,

      normalizeWhitespace:
        normalizedOptions.normalizeWhitespace,

      collapseWhitespace:
        normalizedOptions.collapseWhitespace,

      trimWhitespace:
        normalizedOptions.trimWhitespace,

      createLowercaseView:
        normalizedOptions.createLowercaseView,

      createCompactView:
        normalizedOptions.createCompactView,

      compactSeparators:
        normalizedOptions.compactSeparators,
    },
  };
}

function createEmptyNormalizationResult(
  input,
  options
) {
  const originalText =
    typeof input === "string"
      ? input
      : "";

  return {
    version: NORMALIZATION_VERSION,

    originalText: "",

    normalizedText: "",

    lowercaseText: "",

    compactText: "",

    mappings: [],

    compactMappings: [],

    truncated:
      typeof input === "string" &&
      input.length > options.maxInputCharacters,

    stats: createNormalizationStats(
      originalText,
      "",
      "",
      false
    ),

    options: {
      unicodeNormalization:
        options.unicodeNormalization,

      removeInvisibleCharacters:
        options.removeInvisibleCharacters,

      removeControlCharacters:
        options.removeControlCharacters,

      normalizePunctuation:
        options.normalizePunctuation,

      normalizeWhitespace:
        options.normalizeWhitespace,

      collapseWhitespace:
        options.collapseWhitespace,

      trimWhitespace:
        options.trimWhitespace,

      createLowercaseView:
        options.createLowercaseView,

      createCompactView:
        options.createCompactView,

      compactSeparators:
        options.compactSeparators,
    },
  };
}

/**
 * Normalize text for case-insensitive matching.
 *
 * @param {string} input
 * @param {object} options
 * @returns {string}
 */
export function normalizeForMatching(input, options = {}) {
  const result = normalizeText(input, {
    ...options,
    createLowercaseView: true,
    createCompactView: false,
  });

  return result.lowercaseText;
}

/**
 * Create a compact representation intended for secondary matching.
 *
 * This is useful for values commonly written with separators:
 * - credit cards
 * - IBANs
 * - phone numbers
 * - UUID-like identifiers
 * - serial numbers
 *
 * @param {string} input
 * @param {object} options
 * @returns {string}
 */
export function compactText(input, options = {}) {
  const result = normalizeText(input, {
    ...options,
    createCompactView: true,
  });

  return result.compactText;
}

/**
 * Return the original-text range corresponding to a normalized range.
 *
 * @param {object} normalizationResult
 * @param {number} start
 * @param {number} end
 * @returns {{start:number,end:number}|null}
 */
export function getOriginalRange(
  normalizationResult,
  start,
  end
) {
  if (
    !isNormalizationResult(normalizationResult)
  ) {
    return null;
  }

  return mapNormalizedRangeToOriginal(
    normalizationResult.mappings,
    start,
    end
  );
}

/**
 * Return the original-text range corresponding to a compact-text range.
 *
 * @param {object} normalizationResult
 * @param {number} start
 * @param {number} end
 * @returns {{start:number,end:number}|null}
 */
export function getOriginalRangeFromCompact(
  normalizationResult,
  start,
  end
) {
  if (
    !isNormalizationResult(normalizationResult)
  ) {
    return null;
  }

  return mapNormalizedRangeToOriginal(
    normalizationResult.compactMappings,
    start,
    end
  );
}

/**
 * Return the normalized range corresponding to an original-text range.
 *
 * @param {object} normalizationResult
 * @param {number} start
 * @param {number} end
 * @returns {{start:number,end:number}|null}
 */
export function getNormalizedRange(
  normalizationResult,
  start,
  end
) {
  if (
    !isNormalizationResult(normalizationResult)
  ) {
    return null;
  }

  return mapOriginalRangeToNormalized(
    normalizationResult.mappings,
    start,
    end
  );
}

/**
 * Return the original substring represented by a normalized range.
 *
 * @param {object} normalizationResult
 * @param {number} start
 * @param {number} end
 * @returns {string}
 */
export function getOriginalText(
  normalizationResult,
  start,
  end
) {
  if (
    !isNormalizationResult(normalizationResult)
  ) {
    return "";
  }

  return sliceOriginalByNormalizedRange(
    normalizationResult.originalText,
    normalizationResult.mappings,
    start,
    end
  );
}

/**
 * Return the original substring represented by a compact range.
 *
 * @param {object} normalizationResult
 * @param {number} start,
 * @param {number} end
 * @returns {string}
 */
export function getOriginalTextFromCompact(
  normalizationResult,
  start,
  end
) {
  if (
    !isNormalizationResult(normalizationResult)
  ) {
    return "";
  }

  return sliceOriginalByNormalizedRange(
    normalizationResult.originalText,
    normalizationResult.compactMappings,
    start,
    end
  );
}

/**
 * Check whether a value looks like a valid normalization result.
 *
 * @param {unknown} value
 * @returns {boolean}
 */
export function isNormalizationResult(value) {
  return (
    isObject(value) &&
    value.version === NORMALIZATION_VERSION &&
    typeof value.originalText === "string" &&
    typeof value.normalizedText === "string" &&
    typeof value.lowercaseText === "string" &&
    typeof value.compactText === "string" &&
    Array.isArray(value.mappings) &&
    Array.isArray(value.compactMappings)
  );
}

/**
 * Return the normalization engine version.
 *
 * @returns {number}
 */
export function getNormalizationVersion() {
  return NORMALIZATION_VERSION;
}

/**
 * Return immutable default normalization settings.
 *
 * @returns {object}
 */
export function getDefaultNormalizationOptions() {
  return {
    ...DEFAULT_OPTIONS,
  };
}

/**
 * Detect whether a string contains characters that normalization
 * intentionally removes.
 *
 * This is useful for telemetry-free diagnostics and testing.
 *
 * @param {string} input
 * @returns {boolean}
 */
export function containsInvisibleCharacters(input) {
  if (typeof input !== "string" || input.length === 0) {
    return false;
  }

  for (const character of input) {
    const codePoint = character.codePointAt(0);

    if (isZeroWidthCodePoint(codePoint)) {
      return true;
    }
  }

  return false;
}

/**
 * Detect whether a string contains C0/C1/control characters that
 * the normalizer removes.
 *
 * @param {string} input
 * @returns {boolean}
 */
export function containsRemovableControlCharacters(input) {
  if (typeof input !== "string" || input.length === 0) {
    return false;
  }

  for (const character of input) {
    const codePoint = character.codePointAt(0);

    if (isControlCodePoint(codePoint)) {
      return true;
    }
  }

  return false;
}

/**
 * Return a compact diagnostics object without returning text content.
 *
 * This is safe to use for debugging because it contains lengths and
 * boolean properties only.
 *
 * @param {object} normalizationResult
 * @returns {object}
 */
export function getNormalizationDiagnostics(
  normalizationResult
) {
  if (
    !isNormalizationResult(normalizationResult)
  ) {
    return {
      valid: false,
      version: NORMALIZATION_VERSION,
    };
  }

  return {
    valid: true,
    version: normalizationResult.version,
    originalLength:
      normalizationResult.originalText.length,
    normalizedLength:
      normalizationResult.normalizedText.length,
    lowercaseLength:
      normalizationResult.lowercaseText.length,
    compactLength:
      normalizationResult.compactText.length,
    mappingCount:
      normalizationResult.mappings.length,
    compactMappingCount:
      normalizationResult.compactMappings.length,
    truncated:
      normalizationResult.truncated,
    changed:
      normalizationResult.stats.changed,
    compressionRatio:
      normalizationResult.stats.compressionRatio,
  };
}

/**
 * Validate mapping invariants.
 *
 * Intended for development and automated tests.
 *
 * @param {object} normalizationResult
 * @returns {{valid:boolean,errors:string[]}}
 */
export function validateNormalizationResult(
  normalizationResult
) {
  const errors = [];

  if (!isNormalizationResult(normalizationResult)) {
    return {
      valid: false,
      errors: ["Invalid normalization result."],
    };
  }

  let previousNormalizedEnd = 0;
  let previousOriginalEnd = 0;

  for (const segment of normalizationResult.mappings) {
    if (
      !Number.isInteger(segment.normalizedStart) ||
      !Number.isInteger(segment.normalizedEnd) ||
      !Number.isInteger(segment.originalStart) ||
      !Number.isInteger(segment.originalEnd)
    ) {
      errors.push(
        "Normalization mapping contains non-integer offsets."
      );
      continue;
    }

    if (
      segment.normalizedStart < 0 ||
      segment.normalizedEnd <= segment.normalizedStart
    ) {
      errors.push(
        "Normalization mapping contains an invalid normalized range."
      );
    }

    if (
      segment.originalStart < 0 ||
      segment.originalEnd <= segment.originalStart
    ) {
      errors.push(
        "Normalization mapping contains an invalid original range."
      );
    }

    if (
      segment.normalizedStart < previousNormalizedEnd
    ) {
      errors.push(
        "Normalization mappings are not ordered by normalized offset."
      );
    }

    if (
      segment.originalStart < previousOriginalEnd
    ) {
      errors.push(
        "Normalization mappings are not ordered by original offset."
      );
    }

    if (
      segment.normalizedEnd >
      normalizationResult.normalizedText.length
    ) {
      errors.push(
        "Normalization mapping exceeds normalized text length."
      );
    }

    if (
      segment.originalEnd >
      normalizationResult.originalText.length
    ) {
      errors.push(
        "Normalization mapping exceeds original text length."
      );
    }

    previousNormalizedEnd = segment.normalizedEnd;
    previousOriginalEnd = segment.originalEnd;
  }

  let previousCompactEnd = 0;

  for (const segment of normalizationResult.compactMappings) {
    if (
      !Number.isInteger(segment.normalizedStart) ||
      !Number.isInteger(segment.normalizedEnd) ||
      !Number.isInteger(segment.originalStart) ||
      !Number.isInteger(segment.originalEnd)
    ) {
      errors.push(
        "Compact mapping contains non-integer offsets."
      );
      continue;
    }

    if (
      segment.normalizedStart < previousCompactEnd
    ) {
      errors.push(
        "Compact mappings are not ordered by compact offset."
      );
    }

    if (
      segment.normalizedEnd >
      normalizationResult.compactText.length
    ) {
      errors.push(
        "Compact mapping exceeds compact text length."
      );
    }

    if (
      segment.originalEnd >
      normalizationResult.originalText.length
    ) {
      errors.push(
        "Compact mapping exceeds original text length."
      );
    }

    previousCompactEnd = segment.normalizedEnd;
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

/**
 * Export low-level mapping helpers for the matcher.
 *
 * These functions do not expose or persist sensitive values.
 */
export {
  mapNormalizedRangeToOriginal,
  mapOriginalRangeToNormalized,
};
