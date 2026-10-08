import {
  SCAN_LIMITS,
  FILE_SCAN_DEFAULTS,
  PROTECTION_DEFAULTS,
  ACTIONS
} from "../config/defaults.js";

import {
  EVENT_TYPES,
  SOURCE_TYPES
} from "../config/constants.js";

const FILE_INPUT_SELECTOR = [
  "input[type='file']",
  "[role='button'][aria-haspopup='dialog']"
].join(",");

const TEXT_FILE_EXTENSIONS = new Set([
  "txt",
  "text",
  "csv",
  "tsv",
  "log",

  "json",
  "jsonl",
  "ndjson",

  "xml",
  "html",
  "htm",
  "xhtml",

  "css",
  "scss",
  "sass",
  "less",

  "js",
  "jsx",
  "mjs",
  "cjs",

  "ts",
  "tsx",

  "java",
  "kt",
  "kts",

  "c",
  "h",
  "cc",
  "cpp",
  "cxx",
  "hpp",

  "cs",
  "go",
  "rs",
  "swift",

  "php",
  "rb",
  "py",
  "pyw",

  "sh",
  "bash",
  "zsh",
  "fish",

  "ps1",
  "psm1",
  "bat",
  "cmd",

  "sql",

  "yaml",
  "yml",

  "toml",
  "ini",
  "cfg",
  "conf",

  "env",

  "md",
  "markdown",

  "rst",

  "dockerfile",

  "tf",
  "tfvars",

  "properties",
  "gradle",

  "graphql",
  "gql"
]);

const TEXT_MIME_TYPES = new Set([
  "text/plain",
  "text/csv",
  "text/tab-separated-values",
  "text/html",
  "text/css",
  "text/javascript",
  "application/javascript",
  "application/x-javascript",
  "application/json",
  "application/ld+json",
  "application/xml",
  "text/xml",
  "application/x-yaml",
  "text/yaml",
  "application/sql",
  "text/x-sql",
  "text/markdown"
]);

const BINARY_MIME_PREFIXES = Object.freeze([
  "image/",
  "audio/",
  "video/",
  "font/"
]);

const DEFAULT_FILE_COUNT_LIMIT = 10;

const state = {
  initialized: false,
  destroyed: false,

  config: {
    enabled: PROTECTION_DEFAULTS.enabled,

    scanUploads: PROTECTION_DEFAULTS.scanUpload,

    mode: PROTECTION_DEFAULTS.mode,

    defaultAction: ACTIONS.WARN,

    fileScan: {
      ...FILE_SCAN_DEFAULTS
    }
  },

  callbacks: {
    onFileSelected: null,
    onScanFile: null,
    onFileWarning: null,
    onAllowed: null,
    onBlocked: null,
    onMasked: null,
    onError: null,
    onEvent: null
  },

  listeners: [],

  trackedInputs: new Set(),
  inputState: new WeakMap(),

  processingFiles: false,

  counters: {
    fileInputsDetected: 0,
    fileInputChanges: 0,

    filesDetected: 0,
    filesAccepted: 0,
    filesBlocked: 0,
    filesWarned: 0,
    filesMasked: 0,

    textFilesDetected: 0,
    binaryFilesDetected: 0,

    oversizedFiles: 0,
    oversizedDrops: 0,
    tooManyFiles: 0,

    unsupportedFiles: 0,
    unreadableFiles: 0,

    emptyFiles: 0,

    scanRequests: 0,
    scanFailures: 0,

    errors: 0
  }
};

function now() {
  return Date.now();
}

function createFileOperationId() {
  return `upload_${now()}_${Math.random()
    .toString(36)
    .slice(2, 10)}`;
}

function isObject(value) {
  return value !== null && typeof value === "object";
}

function isElement(value) {
  return (
    value instanceof Element ||
    value instanceof HTMLElement ||
    value instanceof HTMLInputElement
  );
}

function isConnectedElement(element) {
  return Boolean(
    element &&
    typeof element.isConnected === "boolean" &&
    element.isConnected
  );
}

function safeCallback(callback, payload) {
  if (typeof callback !== "function") {
    return undefined;
  }

  try {
    return callback(payload);
  } catch (error) {
    handleError(error, "callback");
    return undefined;
  }
}

function handleError(error, context = "unknown") {
  state.counters.errors += 1;

  const payload = {
    type: EVENT_TYPES.ERROR,
    sourceType: SOURCE_TYPES.UPLOAD,
    context,
    error:
      error instanceof Error
        ? error.message
        : String(error),
    timestamp: now()
  };

  safeCallback(state.callbacks.onError, payload);
  safeCallback(state.callbacks.onEvent, payload);
}

function emitEvent(type, payload = {}) {
  const event = {
    type,
    sourceType: SOURCE_TYPES.UPLOAD,
    timestamp: now(),
    ...payload
  };

  safeCallback(state.callbacks.onEvent, event);

  return event;
}

function normalizeAction(action) {
  switch (action) {
    case ACTIONS.ALLOW:
    case ACTIONS.WARN:
    case ACTIONS.MASK:
    case ACTIONS.BLOCK:
      return action;

    default:
      return state.config.defaultAction || ACTIONS.WARN;
  }
}

function getMaximumFileSize() {
  const configuredLimit = Number(
    state.config.fileScan?.maxFileBytes
  );

  if (
    Number.isFinite(configuredLimit) &&
    configuredLimit > 0
  ) {
    return Math.min(
      configuredLimit,
      SCAN_LIMITS.maxFileBytes
    );
  }

  return SCAN_LIMITS.maxFileBytes;
}

function getMaximumFileCount() {
  const configuredLimit = Number(
    state.config.fileScan?.maxFilesPerDrop
  );

  if (
    Number.isFinite(configuredLimit) &&
    configuredLimit > 0
  ) {
    return Math.min(configuredLimit, 50);
  }

  return DEFAULT_FILE_COUNT_LIMIT;
}

function getMaximumTextCharacters() {
  return Math.min(
    SCAN_LIMITS.maxTextCharacters,
    SCAN_LIMITS.maxNormalizedTextCharacters
  );
}

function getFileExtension(fileName) {
  if (!fileName) {
    return "";
  }

  const normalized = String(fileName)
    .trim()
    .toLowerCase();

  if (
    normalized === "dockerfile" ||
    normalized.endsWith("/dockerfile")
  ) {
    return "dockerfile";
  }

  const lastDot = normalized.lastIndexOf(".");

  if (
    lastDot <= 0 ||
    lastDot === normalized.length - 1
  ) {
    return "";
  }

  return normalized.slice(lastDot + 1);
}

function isTextFileByExtension(fileName) {
  const extension = getFileExtension(fileName);

  return TEXT_FILE_EXTENSIONS.has(extension);
}

function isTextFileByMimeType(mimeType) {
  if (!mimeType) {
    return false;
  }

  const normalized = String(mimeType)
    .trim()
    .toLowerCase();

  if (TEXT_MIME_TYPES.has(normalized)) {
    return true;
  }

  return normalized.startsWith("text/");
}

function isBinaryMimeType(mimeType) {
  if (!mimeType) {
    return false;
  }

  const normalized = String(mimeType)
    .trim()
    .toLowerCase();

  return BINARY_MIME_PREFIXES.some((prefix) =>
    normalized.startsWith(prefix)
  );
}

function classifyFile(file) {
  if (!file) {
    return {
      kind: "unknown",
      confidence: 0
    };
  }

  const extension = getFileExtension(file.name);
  const mimeType = String(file.type || "")
    .trim()
    .toLowerCase();

  if (isTextFileByExtension(file.name)) {
    return {
      kind: "text",
      confidence: 0.95,
      extension,
      mimeType
    };
  }

  if (isTextFileByMimeType(mimeType)) {
    return {
      kind: "text",
      confidence: 0.90,
      extension,
      mimeType
    };
  }

  if (isBinaryMimeType(mimeType)) {
    return {
      kind: "binary",
      confidence: 0.90,
      extension,
      mimeType
    };
  }

  if (
    mimeType.startsWith("application/") &&
    extension
  ) {
    return {
      kind: "unknown",
      confidence: 0.50,
      extension,
      mimeType
    };
  }

  return {
    kind: "unknown",
    confidence: 0.25,
    extension,
    mimeType
  };
}

function getSafeFileMetadata(file) {
  if (!file) {
    return null;
  }

  const classification = classifyFile(file);

  return {
    name: String(file.name || "").slice(
      0,
      SCAN_LIMITS.maxFileNameCharacters
    ),

    size:
      Number.isFinite(file.size)
        ? file.size
        : 0,

    type: String(file.type || "")
      .slice(0, 255)
      .toLowerCase(),

    lastModified:
      Number.isFinite(file.lastModified)
        ? file.lastModified
        : 0,

    extension:
      classification.extension || "",

    kind: classification.kind,

    classificationConfidence:
      classification.confidence
  };
}

function getSafeFileMetadataList(files) {
  return Array.from(files || [])
    .map(getSafeFileMetadata)
    .filter(Boolean);
}

function isFileInput(element) {
  if (!isElement(element)) {
    return false;
  }

  if (
    element instanceof HTMLInputElement
  ) {
    return (
      String(element.type || "").toLowerCase() ===
      "file"
    );
  }

  return false;
}

function isDisabledFileInput(input) {
  if (!input) {
    return true;
  }

  return Boolean(
    input.disabled ||
    input.readOnly ||
    input.hidden ||
    input.getAttribute("aria-disabled") === "true"
  );
}

function getInputMetadata(input) {
  if (!input) {
    return null;
  }

  return {
    tagName: String(
      input.tagName || ""
    ).toLowerCase(),

    type: String(
      input.getAttribute?.("type") || ""
    ).toLowerCase(),

    name: String(
      input.getAttribute?.("name") || ""
    ).slice(0, 200),

    id: String(
      input.getAttribute?.("id") || ""
    ).slice(0, 200),

    accept: String(
      input.getAttribute?.("accept") || ""
    ).slice(0, 1000),

    multiple: Boolean(input.multiple),

    disabled: Boolean(input.disabled),

    required: Boolean(input.required)
  };
}

function isUploadInput(input) {
  return (
    isFileInput(input) &&
    !isDisabledFileInput(input)
  );
}

function getFilesFromInput(input) {
  if (!input || !input.files) {
    return [];
  }

  try {
    return Array.from(input.files);
  } catch (error) {
    handleError(error, "getFilesFromInput");
    return [];
  }
}

function getFileCount(files) {
  return Array.isArray(files)
    ? files.length
    : Array.from(files || []).length;
}

function validateFiles(files) {
  const fileList = Array.from(files || []);

  const result = {
    valid: true,
    reason: null,

    files: fileList,

    totalBytes: 0,

    oversizedFiles: [],

    emptyFiles: [],

    unsupportedFiles: [],

    maximumFileSize:
      getMaximumFileSize(),

    maximumFileCount:
      getMaximumFileCount()
  };

  if (
    fileList.length >
    result.maximumFileCount
  ) {
    result.valid = false;
    result.reason = "too_many_files";

    result.rejectedFiles =
      fileList.slice(result.maximumFileCount);

    return result;
  }

  for (const file of fileList) {
    if (!file) {
      continue;
    }

    const size =
      Number(file.size) || 0;

    result.totalBytes += size;

    if (size === 0) {
      result.emptyFiles.push(file);
    }

    if (
      size >
      result.maximumFileSize
    ) {
      result.valid = false;

      result.reason =
        "file_too_large";

      result.oversizedFiles.push(file);

      continue;
    }

    const classification =
      classifyFile(file);

    if (
      classification.kind === "unknown" &&
      state.config.fileScan.rejectUnsupportedFiles
    ) {
      result.valid = false;

      result.reason =
        "unsupported_file_type";

      result.unsupportedFiles.push(file);
    }
  }

  return result;
}

function isLikelyTextFile(file) {
  const classification =
    classifyFile(file);

  return classification.kind === "text";
}

function isLikelyBinaryFile(file) {
  const classification =
    classifyFile(file);

  return classification.kind === "binary";
}

async function readBlobAsText(blob) {
  if (!blob) {
    throw new Error("File is empty or unavailable");
  }

  if (
    typeof blob.text === "function"
  ) {
    return blob.text();
  }

  if (
    typeof FileReader === "undefined"
  ) {
    throw new Error(
      "FileReader is unavailable"
    );
  }

  return new Promise(
    (resolve, reject) => {
      const reader =
        new FileReader();

      reader.onload = () => {
        resolve(
          typeof reader.result === "string"
            ? reader.result
            : ""
        );
      };

      reader.onerror = () => {
        reject(
          reader.error ||
          new Error(
            "Unable to read file"
          )
        );
      };

      reader.onabort = () => {
        reject(
          new Error(
            "File read aborted"
          )
        );
      };

      try {
        reader.readAsText(blob);
      } catch (error) {
        reject(error);
      }
    }
  );
}

async function readFileText(file) {
  if (!file) {
    throw new Error(
      "File is unavailable"
    );
  }

  if (!isLikelyTextFile(file)) {
    throw new Error(
      "File is not classified as text"
    );
  }

  const maximumCharacters =
    getMaximumTextCharacters();

  /*
   * We intentionally read only a bounded Blob slice.
   *
   * This prevents a very large text document from being fully
   * loaded into memory when the scanner only needs the allowed
   * scanning window.
   */
  const estimatedBytes =
    Math.min(
      Number(file.size) || 0,
      maximumCharacters * 4
    );

  const blob =
    typeof file.slice === "function"
      ? file.slice(
          0,
          Math.max(
            estimatedBytes,
            maximumCharacters
          )
        )
      : file;

  const text =
    await readBlobAsText(blob);

  if (
    typeof text !== "string"
  ) {
    return "";
  }

  return text.slice(
    0,
    maximumCharacters
  );
}

function createFilePayload({
  operationId,
  file,
  index,
  total,
  text = "",
  classification = null,
  validation = null
}) {
  return {
    operationId,

    sourceType:
      SOURCE_TYPES.UPLOAD,

    timestamp: now(),

    index,

    total,

    metadata:
      getSafeFileMetadata(file),

    classification,

    validation: validation
      ? {
          valid: Boolean(validation.valid),
          reason:
            validation.reason || null
        }
      : null,

    /*
     * Raw text is intentionally kept in the local callback payload.
     *
     * It must not be passed to the service worker.
     */
    text
  };
}

async function invokeScanCallback(payload) {
  if (
    typeof state.callbacks.onScanFile !==
    "function"
  ) {
    return ACTIONS.BLOCK;
  }

  state.counters.scanRequests += 1;

  try {
    const result =
      await Promise.resolve(
        state.callbacks.onScanFile(
          payload
        )
      );

    return normalizeAction(result);
  } catch (error) {
    state.counters.scanFailures += 1;

    handleError(
      error,
      "scanFileCallback"
    );

    return ACTIONS.BLOCK;
  }
}

async function invokeWarningCallback(payload) {
  if (
    typeof state.callbacks.onFileWarning !==
    "function"
  ) {
    return ACTIONS.BLOCK;
  }

  try {
    const result =
      await Promise.resolve(
        state.callbacks.onFileWarning(
          payload
        )
      );

    return normalizeAction(result);
  } catch (error) {
    handleError(
      error,
      "fileWarningCallback"
    );

    return ACTIONS.BLOCK;
  }
}

function notifyAllowed(payload) {
  state.counters.filesAccepted += 1;

  safeCallback(
    state.callbacks.onAllowed,
    {
      ...payload,
      text: ""
    }
  );

  emitEvent(
    EVENT_TYPES.ACTION_ALLOWED,
    {
      operationId:
        payload.operationId,
      fileIndex:
        payload.index
    }
  );
}

function notifyBlocked(
  payload,
  reason
) {
  state.counters.filesBlocked += 1;

  safeCallback(
    state.callbacks.onBlocked,
    {
      ...payload,
      text: "",
      action: ACTIONS.BLOCK,
      reason
    }
  );

  emitEvent(
    EVENT_TYPES.ACTION_BLOCKED,
    {
      operationId:
        payload.operationId,
      fileIndex:
        payload.index,
      reason
    }
  );
}

function notifyMasked(
  payload,
  reason
) {
  state.counters.filesMasked += 1;

  safeCallback(
    state.callbacks.onMasked,
    {
      ...payload,
      text: "",
      action: ACTIONS.MASK,
      reason
    }
  );

  emitEvent(
    EVENT_TYPES.ACTION_MASKED,
    {
      operationId:
        payload.operationId,
      fileIndex:
        payload.index,
      reason
    }
  );
}

async function processSingleFile(
  file,
  index,
  total,
  operationId,
  validation
) {
  const classification =
    classifyFile(file);

  if (
    classification.kind === "text"
  ) {
    state.counters.textFilesDetected += 1;
  } else if (
    classification.kind === "binary"
  ) {
    state.counters.binaryFilesDetected += 1;
  }

  const basePayload =
    createFilePayload({
      operationId,
      file,
      index,
      total,
      classification,
      validation
    });

  emitEvent(
    EVENT_TYPES.UPLOAD_DETECTED,
    {
      operationId,
      fileIndex: index,
      file: basePayload.metadata,
      classification
    }
  );

  /*
   * Files larger than the configured limit are blocked before
   * any file contents are read.
   */
  if (
    file.size >
    validation.maximumFileSize
  ) {
    state.counters.oversizedFiles += 1;

    notifyBlocked(
      basePayload,
      "file_too_large"
    );

    return ACTIONS.BLOCK;
  }

  if (
    state.config.fileScan.scanFileNames ===
    false &&
    classification.kind === "unknown"
  ) {
    /*
     * Unknown files are not automatically trusted.
     *
     * The policy engine will eventually be able to make a more
     * precise decision from file type and content.
     */
  }

  let text = "";

  if (
    state.config.fileScan.scanTextFiles &&
    classification.kind === "text"
  ) {
    try {
      text =
        await readFileText(file);
    } catch (error) {
      state.counters.unreadableFiles += 1;

      handleError(
        error,
        "readFileText"
      );

      notifyBlocked(
        basePayload,
        "file_read_failed"
      );

      return ACTIONS.BLOCK;
    }
  }

  const payload =
    createFilePayload({
      operationId,
      file,
      index,
      total,
      text,
      classification,
      validation
    });

  let decision =
    await invokeScanCallback(
      payload
    );

  decision =
    normalizeAction(decision);

  if (
    decision === ACTIONS.ALLOW
  ) {
    notifyAllowed(payload);

    return ACTIONS.ALLOW;
  }

  if (
    decision === ACTIONS.WARN
  ) {
    state.counters.filesWarned += 1;

    const warningDecision =
      await invokeWarningCallback({
        ...payload,
        text: ""
      });

    if (
      warningDecision ===
      ACTIONS.ALLOW
    ) {
      notifyAllowed(payload);

      return ACTIONS.ALLOW;
    }

    if (
      warningDecision ===
      ACTIONS.MASK
    ) {
      /*
       * File masking is not performed by this module.
       *
       * The future sanitizer pipeline must create a new sanitized
       * File/Blob before the website receives it.
       */
      notifyBlocked(
        payload,
        "file_masking_requires_sanitized_file"
      );

      return ACTIONS.BLOCK;
    }

    notifyBlocked(
      payload,
      "warning_rejected"
    );

    return ACTIONS.BLOCK;
  }

  if (
    decision === ACTIONS.MASK
  ) {
    /*
     * Do not claim that a file has been masked.
     *
     * A masked file must be generated explicitly by the file
     * sanitization pipeline.
     */
    notifyMasked(
      payload,
      "sanitized_file_generation_required"
    );

    notifyBlocked(
      payload,
      "sanitized_file_generation_required"
    );

    return ACTIONS.BLOCK;
  }

  notifyBlocked(
    payload,
    "policy_block"
  );

  return ACTIONS.BLOCK;
}

async function processFiles(
  files,
  source = "input"
) {
  const fileList =
    Array.from(files || []);

  if (
    fileList.length === 0
  ) {
    return {
      action: ACTIONS.ALLOW,
      processed: 0,
      blocked: 0,
      allowed: 0
    };
  }

  if (
    state.processingFiles
  ) {
    return {
      action: ACTIONS.BLOCK,
      processed: 0,
      blocked: fileList.length,
      allowed: 0,
      reason: "upload_already_processing"
    };
  }

  state.processingFiles = true;

  const operationId =
    createFileOperationId();

  const validation =
    validateFiles(fileList);

  try {
    state.counters.filesDetected +=
      fileList.length;

    if (
      fileList.length >
      validation.maximumFileCount
    ) {
      state.counters.tooManyFiles += 1;

      for (
        const file of fileList
      ) {
        notifyBlocked(
          createFilePayload({
            operationId,
            file,
            index: 0,
            total: fileList.length,
            classification:
              classifyFile(file),
            validation
          }),
          "too_many_files"
        );
      }

      return {
        action: ACTIONS.BLOCK,
        processed: 0,
        blocked: fileList.length,
        allowed: 0,
        reason: "too_many_files"
      };
    }

    if (
      !validation.valid
    ) {
      const reason =
        validation.reason ||
        "invalid_file";

      for (
        let index = 0;
        index < fileList.length;
        index += 1
      ) {
        const file =
          fileList[index];

        const payload =
          createFilePayload({
            operationId,
            file,
            index,
            total: fileList.length,
            classification:
              classifyFile(file),
            validation
          });

        notifyBlocked(
          payload,
          reason
        );
      }

      return {
        action: ACTIONS.BLOCK,
        processed: 0,
        blocked: fileList.length,
        allowed: 0,
        reason
      };
    }

    emitEvent(
      EVENT_TYPES.SCAN_STARTED,
      {
        operationId,
        source,
        fileCount:
          fileList.length
      }
    );

    const results = [];

    for (
      let index = 0;
      index < fileList.length;
      index += 1
    ) {
      const file =
        fileList[index];

      const result =
        await processSingleFile(
          file,
          index,
          fileList.length,
          operationId,
          validation
        );

      results.push(result);

      /*
       * If one file is blocked, the whole multi-file upload is
       * considered blocked.
       *
       * This prevents a mixed upload where one malicious/sensitive
       * file is blocked but another file reaches the AI platform.
       */
      if (
        result === ACTIONS.BLOCK
      ) {
        for (
          let remaining =
            index + 1;
          remaining < fileList.length;
          remaining += 1
        ) {
          const remainingFile =
            fileList[remaining];

          notifyBlocked(
            createFilePayload({
              operationId,
              file: remainingFile,
              index: remaining,
              total: fileList.length,
              classification:
                classifyFile(
                  remainingFile
                ),
              validation
            }),
            "batch_upload_blocked"
          );
        }

        emitEvent(
          EVENT_TYPES.SCAN_COMPLETED,
          {
            operationId,
            source,
            result:
              ACTIONS.BLOCK,
            fileCount:
              fileList.length
          }
        );

        return {
          action: ACTIONS.BLOCK,
          processed:
            index + 1,
          blocked:
            fileList.length - index,
          allowed: 0,
          results
        };
      }
    }

    emitEvent(
      EVENT_TYPES.SCAN_COMPLETED,
      {
        operationId,
        source,
        result:
          ACTIONS.ALLOW,
        fileCount:
          fileList.length
      }
    );

    return {
      action: ACTIONS.ALLOW,
      processed:
        fileList.length,
      blocked: 0,
      allowed:
        fileList.length,
      results
    };
  } catch (error) {
    state.counters.scanFailures += 1;

    handleError(
      error,
      "processFiles"
    );

    emitEvent(
      EVENT_TYPES.SCAN_FAILED,
      {
        operationId,
        source,
        reason:
          "upload_processing_failed"
      }
    );

    return {
      action: ACTIONS.BLOCK,
      processed: 0,
      blocked:
        fileList.length,
      allowed: 0,
      reason:
        "upload_processing_failed"
    };
  } finally {
    state.processingFiles = false;
  }
}

async function handleFileInputChange(
  event
) {
  const input =
    event?.target;

  if (
    !isUploadInput(input)
  ) {
    return;
  }

  state.counters.fileInputChanges +=
    1;

  const files =
    getFilesFromInput(input);

  if (
    files.length === 0
  ) {
    return;
  }

  const metadata =
    getSafeFileMetadataList(files);

  emitEvent(
    EVENT_TYPES.UPLOAD_DETECTED,
    {
      source: "file-input",
      fileCount:
        files.length,
      files: metadata
    }
  );

  /*
   * IMPORTANT:
   *
   * The browser will use the actual input FileList when the page
   * submits the form or application upload action.
   *
   * We therefore need the future content.js/policy integration to
   * prevent the application from submitting until this operation
   * has completed.
   */

  const result =
    await processFiles(
      files,
      "file-input"
    );

  if (
    result.action === ACTIONS.BLOCK
  ) {
    /*
     * Clearing the file input removes the selected sensitive file
     * from the DOM control.
     *
     * This is intentional for a blocked upload.
     */
    try {
      input.value = "";
    } catch (error) {
      handleError(
        error,
        "clearBlockedFileInput"
      );
    }
  }

  safeCallback(
    state.callbacks.onFileSelected,
    {
      sourceType:
        SOURCE_TYPES.UPLOAD,

      action:
        result.action,

      source: "file-input",

      result,

      inputMetadata:
        getInputMetadata(input),

      /*
       * Never expose the actual File objects here.
       */
      files: metadata
    }
  );
}

function handleClick(event) {
  if (
    !state.initialized ||
    state.destroyed
  ) {
    return;
  }

  const target =
    event?.target;

  if (
    !target ||
    !isElement(target)
  ) {
    return;
  }

  const fileInput =
    isFileInput(target)
      ? target
      : target.closest?.(
          "input[type='file']"
        );

  if (
    fileInput &&
    isUploadInput(fileInput)
  ) {
    state.counters.fileInputsDetected +=
      1;
  }
}

function trackFileInput(input) {
  if (
    !isUploadInput(input)
  ) {
    return false;
  }

  if (
    state.trackedInputs.has(input)
  ) {
    return true;
  }

  state.trackedInputs.add(input);

  state.inputState.set(
    input,
    {
      registeredAt: now(),
      lastFileCount: 0
    }
  );

  state.counters.fileInputsDetected +=
    1;

  return true;
}

function scanExistingFileInputs() {
  if (
    typeof document ===
    "undefined"
  ) {
    return;
  }

  const inputs =
    document.querySelectorAll(
      "input[type='file']"
    );

  for (
    const input of inputs
  ) {
    trackFileInput(input);
  }
}

function handleMutationRecords(
  records
) {
  for (
    const record of records
  ) {
    if (
      record.type !==
      "childList"
    ) {
      continue;
    }

    for (
      const node of record.addedNodes
    ) {
      if (
        !isElement(node)
      ) {
        continue;
      }

      if (
        isFileInput(node)
      ) {
        trackFileInput(node);
      }

      if (
        typeof node.querySelectorAll ===
        "function"
      ) {
        const inputs =
          node.querySelectorAll(
            "input[type='file']"
          );

        for (
          const input of inputs
        ) {
          trackFileInput(input);
        }
      }
    }
  }

  cleanupDisconnectedInputs();
}

function cleanupDisconnectedInputs() {
  for (
    const input of state.trackedInputs
  ) {
    if (
      !isConnectedElement(input)
    ) {
      state.trackedInputs.delete(
        input
      );
    }
  }
}

function installMutationObserver() {
  if (
    typeof MutationObserver ===
    "undefined" ||
    !document.documentElement
  ) {
    return;
  }

  const observer =
    new MutationObserver(
      handleMutationRecords
    );

  observer.observe(
    document.documentElement,
    {
      childList: true,
      subtree: true
    }
  );

  state.listeners.push({
    target: observer,
    observer: true
  });
}

function installListeners() {
  removeListeners();

  if (
    typeof document ===
    "undefined"
  ) {
    return;
  }

  document.addEventListener(
    "change",
    handleFileInputChange,
    true
  );

  state.listeners.push({
    target: document,
    eventName: "change",
    handler:
      handleFileInputChange,
    options: true
  });

  document.addEventListener(
    "click",
    handleClick,
    true
  );

  state.listeners.push({
    target: document,
    eventName: "click",
    handler: handleClick,
    options: true
  });

  installMutationObserver();
}

function removeListeners() {
  for (
    const listener of state.listeners
  ) {
    try {
      if (
        listener.observer &&
        listener.target
      ) {
        listener.target.disconnect();
        continue;
      }

      if (
        listener.target &&
        typeof listener.target.removeEventListener ===
          "function"
      ) {
        listener.target.removeEventListener(
          listener.eventName,
          listener.handler,
          listener.options
        );
      }
    } catch {
      /*
       * Ignore cleanup failures.
       */
    }
  }

  state.listeners = [];
}

function mergeConfig(config = {}) {
  if (
    !isObject(config)
  ) {
    return;
  }

  if (
    typeof config.enabled ===
    "boolean"
  ) {
    state.config.enabled =
      config.enabled;
  }

  if (
    typeof config.scanUploads ===
    "boolean"
  ) {
    state.config.scanUploads =
      config.scanUploads;
  }

  if (
    typeof config.mode ===
    "string"
  ) {
    state.config.mode =
      config.mode;
  }

  if (
    typeof config.defaultAction ===
    "string"
  ) {
    state.config.defaultAction =
      normalizeAction(
        config.defaultAction
      );
  }

  if (
    isObject(config.fileScan)
  ) {
    state.config.fileScan = {
      ...state.config.fileScan,
      ...config.fileScan
    };
  }
}

function setCallbacks(
  callbacks = {}
) {
  if (
    !isObject(callbacks)
  ) {
    return;
  }

  const callbackNames = [
    "onFileSelected",
    "onScanFile",
    "onFileWarning",
    "onAllowed",
    "onBlocked",
    "onMasked",
    "onError",
    "onEvent"
  ];

  for (
    const callbackName of
      callbackNames
  ) {
    if (
      callbacks[callbackName] ===
        null ||
      typeof callbacks[callbackName] ===
        "function"
    ) {
      state.callbacks[
        callbackName
      ] = callbacks[
        callbackName
      ];
    }
  }
}

function shouldProcessUploads() {
  if (
    !state.initialized ||
    state.destroyed
  ) {
    return false;
  }

  if (
    !state.config.enabled
  ) {
    return false;
  }

  if (
    state.config.mode ===
    "disabled"
  ) {
    return false;
  }

  if (
    !state.config.scanUploads
  ) {
    return false;
  }

  return true;
}

function initialize(options = {}) {
  if (
    state.initialized &&
    !state.destroyed
  ) {
    if (options.config) {
      mergeConfig(
        options.config
      );
    }

    if (options.callbacks) {
      setCallbacks(
        options.callbacks
      );
    }

    scanExistingFileInputs();

    return getUploadMonitorDiagnostics();
  }

  state.destroyed = false;

  mergeConfig(
    options.config || {}
  );

  setCallbacks(
    options.callbacks || {}
  );

  installListeners();

  state.initialized = true;

  scanExistingFileInputs();

  emitEvent(
    EVENT_TYPES.CONTENT_READY,
    {
      component:
        "upload-monitor"
    }
  );

  return getUploadMonitorDiagnostics();
}

function destroy() {
  removeListeners();

  state.trackedInputs.clear();

  state.processingFiles = false;

  state.initialized = false;
  state.destroyed = true;

  for (
    const callbackName of
      Object.keys(
        state.callbacks
      )
  ) {
    state.callbacks[
      callbackName
    ] = null;
  }
}

function updateConfig(
  config = {}
) {
  mergeConfig(config);

  if (
    state.initialized &&
    !state.destroyed
  ) {
    installListeners();
    scanExistingFileInputs();
  }

  return getUploadMonitorDiagnostics();
}

function getUploadMonitorConfig() {
  return {
    enabled:
      state.config.enabled,

    scanUploads:
      state.config.scanUploads,

    mode:
      state.config.mode,

    defaultAction:
      state.config.defaultAction,

    fileScan: {
      ...state.config.fileScan
    }
  };
}

function getUploadMonitorDiagnostics() {
  return {
    initialized:
      state.initialized,

    destroyed:
      state.destroyed,

    processingFiles:
      state.processingFiles,

    trackedFileInputs:
      state.trackedInputs.size,

    config:
      getUploadMonitorConfig(),

    counters: {
      ...state.counters
    },

    listeners:
      state.listeners.length,

    callbacks: {
      onFileSelected:
        typeof state.callbacks
          .onFileSelected ===
        "function",

      onScanFile:
        typeof state.callbacks
          .onScanFile ===
        "function",

      onFileWarning:
        typeof state.callbacks
          .onFileWarning ===
        "function",

      onAllowed:
        typeof state.callbacks
          .onAllowed ===
        "function",

      onBlocked:
        typeof state.callbacks
          .onBlocked ===
        "function",

      onMasked:
        typeof state.callbacks
          .onMasked ===
        "function",

      onError:
        typeof state.callbacks
          .onError ===
        "function",

      onEvent:
        typeof state.callbacks
          .onEvent ===
        "function"
    }
  };
}

function getUploadCapabilities() {
  return {
    fileInputMonitoring: true,

    dynamicFileInputMonitoring:
      true,

    multipleFiles:
      true,

    localFileReading:
      true,

    boundedTextReading:
      true,

    binaryClassification:
      true,

    filenameInspection:
      true,

    metadataInspection:
      true,

    rawFileTransferToBackground:
      false,

    persistentFileStorage:
      false,

    networkScanning:
      false,

    fileMasking:
      false,

    sanitizedFileReplacement:
      false
  };
}

function isUploadMonitorInitialized() {
  return (
    state.initialized &&
    !state.destroyed
  );
}

function isProcessingUploads() {
  return state.processingFiles;
}

function getTrackedFileInputs() {
  return Array.from(
    state.trackedInputs
  ).filter(
    isConnectedElement
  );
}

function getFileInputState(input) {
  if (!input) {
    return null;
  }

  return (
    state.inputState.get(
      input
    ) || null
  );
}

function getFileClassification(
  file
) {
  return classifyFile(file);
}

function getFileExtensionSafe(
  fileName
) {
  return getFileExtension(
    fileName
  );
}

function isTextFile(file) {
  return isLikelyTextFile(file);
}

function isBinaryFile(file) {
  return isLikelyBinaryFile(file);
}

function getFileSizeLimit() {
  return getMaximumFileSize();
}

function getFileCountLimit() {
  return getMaximumFileCount();
}

async function scanFiles(
  files,
  source = "manual"
) {
  if (
    !shouldProcessUploads()
  ) {
    return {
      action: ACTIONS.BLOCK,
      processed: 0,
      blocked:
        getFileCount(files),
      allowed: 0,
      reason:
        "upload_protection_disabled"
    };
  }

  return processFiles(
    files,
    source
  );
}

export {
  initialize,
  destroy,
  updateConfig,
  setCallbacks,

  scanFiles,

  getUploadMonitorConfig,
  getUploadMonitorDiagnostics,
  getUploadCapabilities,

  isUploadMonitorInitialized,
  isProcessingUploads,

  getTrackedFileInputs,
  getFileInputState,

  getFileMetadata:
    getSafeFileMetadata,

  getSafeFileMetadataList,

  getFileClassification,
  getFileExtensionSafe,

  isTextFile,
  isBinaryFile,

  getFileSizeLimit,
  getFileCountLimit,

  validateFiles,

  readFileText
};
