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

import {
  getActiveInput,
  getInputMetadata,
  isSupportedInput
} from "./input-monitor.js";

import {
  insertPasteText,
  isClipboardTextWithinLimit
} from "./paste-monitor.js";

const DROP_EVENT_NAMES = Object.freeze([
  "dragenter",
  "dragover",
  "dragleave",
  "drop"
]);

const SUPPORTED_TEXT_TYPES = Object.freeze([
  "text/plain"
]);

const UNSUPPORTED_DROP_TYPES = Object.freeze([
  "text/html"
]);

const state = {
  initialized: false,
  destroyed: false,

  config: {
    enabled: PROTECTION_DEFAULTS.enabled,
    scanDragDrop: PROTECTION_DEFAULTS.scanDragDrop,
    mode: PROTECTION_DEFAULTS.mode,
    defaultAction: ACTIONS.WARN,

    fileScan: {
      ...FILE_SCAN_DEFAULTS
    }
  },

  callbacks: {
    onDrop: null,
    onFileDrop: null,
    onWarning: null,
    onBlocked: null,
    onAllowed: null,
    onMasked: null,
    onEvent: null,
    onError: null
  },

  listeners: [],

  dragDepth: 0,
  activeDragTarget: null,
  lastDropTarget: null,

  processingDrop: false,
  pendingDropId: null,

  counters: {
    dragEnter: 0,
    dragOver: 0,
    dragLeave: 0,
    drop: 0,

    textDrops: 0,
    fileDrops: 0,
    blockedDrops: 0,
    warnedDrops: 0,
    maskedDrops: 0,
    allowedDrops: 0,
    rejectedDrops: 0,

    oversizedTextDrops: 0,
    oversizedFileDrops: 0,
    unsupportedDrops: 0,

    errors: 0
  }
};

function now() {
  return Date.now();
}

function createDropId() {
  return `drop_${now()}_${Math.random().toString(36).slice(2, 10)}`;
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
    sourceType: SOURCE_TYPES.DROP,
    context,
    error: error instanceof Error ? error.message : String(error),
    timestamp: now()
  };

  safeCallback(state.callbacks.onError, payload);
  safeCallback(state.callbacks.onEvent, payload);
}

function isObject(value) {
  return value !== null && typeof value === "object";
}

function isElement(value) {
  return (
    value instanceof Element ||
    value instanceof HTMLElement ||
    value instanceof HTMLInputElement ||
    value instanceof HTMLTextAreaElement
  );
}

function isConnectedElement(element) {
  return Boolean(
    element &&
    typeof element.isConnected === "boolean" &&
    element.isConnected
  );
}

function isEditableTarget(element) {
  if (!isElement(element)) {
    return false;
  }

  try {
    return isSupportedInput(element);
  } catch {
    return false;
  }
}

function findEditableTarget(startElement) {
  if (!startElement) {
    return getActiveInput();
  }

  if (isEditableTarget(startElement)) {
    return startElement;
  }

  if (typeof startElement.closest === "function") {
    const closestEditable = startElement.closest(
      [
        "textarea",
        "input:not([type='password']):not([type='hidden'])",
        "[contenteditable='true']",
        "[contenteditable='plaintext-only']",
        "[role='textbox']"
      ].join(",")
    );

    if (isEditableTarget(closestEditable)) {
      return closestEditable;
    }
  }

  const activeInput = getActiveInput();

  if (isEditableTarget(activeInput)) {
    return activeInput;
  }

  return null;
}

function getSafeTargetMetadata(target) {
  if (!target || !isElement(target)) {
    return null;
  }

  let metadata = null;

  try {
    metadata = getInputMetadata(target);
  } catch {
    metadata = null;
  }

  if (!metadata) {
    return {
      tagName: String(target.tagName || "").toLowerCase(),
      inputType: String(target.getAttribute?.("type") || "").toLowerCase(),
      role: String(target.getAttribute?.("role") || "").toLowerCase(),
      contentEditable:
        target.getAttribute?.("contenteditable") === "true" ||
        target.getAttribute?.("contenteditable") === "plaintext-only"
    };
  }

  return {
    tagName: metadata.tagName || "",
    inputType: metadata.inputType || "",
    role: metadata.role || "",
    contentEditable: Boolean(metadata.contentEditable),
    isSearchInput: Boolean(metadata.isSearchInput),
    isActionControl: Boolean(metadata.isActionControl)
  };
}

function getDataTransferTypes(dataTransfer) {
  if (!dataTransfer || !dataTransfer.types) {
    return [];
  }

  try {
    return Array.from(dataTransfer.types)
      .map((type) => String(type || "").toLowerCase())
      .filter(Boolean);
  } catch {
    return [];
  }
}

function hasFiles(dataTransfer) {
  if (!dataTransfer) {
    return false;
  }

  try {
    if (dataTransfer.files && dataTransfer.files.length > 0) {
      return true;
    }
  } catch {
    return false;
  }

  return getDataTransferTypes(dataTransfer).includes("files");
}

function hasText(dataTransfer) {
  const types = getDataTransferTypes(dataTransfer);

  return (
    types.includes("text/plain") ||
    types.includes("text") ||
    types.includes("text/uri-list")
  );
}

function hasHtml(dataTransfer) {
  const types = getDataTransferTypes(dataTransfer);

  return UNSUPPORTED_DROP_TYPES.some((type) => types.includes(type));
}

function hasSupportedText(dataTransfer) {
  if (!dataTransfer) {
    return false;
  }

  const types = getDataTransferTypes(dataTransfer);

  return SUPPORTED_TEXT_TYPES.some((type) => types.includes(type));
}

function extractPlainText(dataTransfer) {
  if (!dataTransfer) {
    return "";
  }

  try {
    if (typeof dataTransfer.getData !== "function") {
      return "";
    }

    const text = dataTransfer.getData("text/plain");

    if (typeof text === "string" && text.length > 0) {
      return text;
    }
  } catch (error) {
    handleError(error, "extractPlainText");
  }

  return "";
}

function extractUriList(dataTransfer) {
  if (!dataTransfer) {
    return "";
  }

  try {
    if (typeof dataTransfer.getData !== "function") {
      return "";
    }

    const uriList = dataTransfer.getData("text/uri-list");

    if (typeof uriList !== "string") {
      return "";
    }

    return uriList
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean)
      .filter((line) => !line.startsWith("#"))
      .join("\n");
  } catch (error) {
    handleError(error, "extractUriList");
    return "";
  }
}

function getDroppedFiles(dataTransfer) {
  if (!dataTransfer || !dataTransfer.files) {
    return [];
  }

  try {
    return Array.from(dataTransfer.files);
  } catch (error) {
    handleError(error, "getDroppedFiles");
    return [];
  }
}

function getFileMetadata(file) {
  if (!file) {
    return null;
  }

  return {
    name: String(file.name || "").slice(
      0,
      SCAN_LIMITS.maxFileNameCharacters
    ),
    size: Number.isFinite(file.size) ? file.size : 0,
    type: String(file.type || "").toLowerCase(),
    lastModified:
      Number.isFinite(file.lastModified) ? file.lastModified : 0
  };
}

function getSafeFileMetadata(files) {
  return files
    .map((file) => getFileMetadata(file))
    .filter(Boolean);
}

function getMaximumFileSize() {
  const configuredLimit = Number(state.config.fileScan?.maxFileBytes);

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
  const configuredCount = Number(
    state.config.fileScan?.maxFilesPerDrop
  );

  if (
    Number.isFinite(configuredCount) &&
    configuredCount > 0
  ) {
    return Math.min(configuredCount, 50);
  }

  return 10;
}

function validateDroppedFiles(files) {
  const maximumFileSize = getMaximumFileSize();
  const maximumFileCount = getMaximumFileCount();

  const result = {
    valid: true,
    reason: null,
    files,
    oversizedFiles: [],
    rejectedFiles: [],
    totalBytes: 0
  };

  if (files.length === 0) {
    return result;
  }

  if (files.length > maximumFileCount) {
    result.valid = false;
    result.reason = "too_many_files";
    result.rejectedFiles = files.slice(maximumFileCount);
    return result;
  }

  for (const file of files) {
    if (!file) {
      continue;
    }

    const size = Number(file.size) || 0;

    result.totalBytes += size;

    if (size > maximumFileSize) {
      result.valid = false;
      result.reason = "file_too_large";
      result.oversizedFiles.push(file);
    }
  }

  return result;
}

function validateDropTarget(target) {
  if (!target) {
    return {
      valid: false,
      reason: "no_target"
    };
  }

  if (!isConnectedElement(target)) {
    return {
      valid: false,
      reason: "target_disconnected"
    };
  }

  if (!isEditableTarget(target)) {
    return {
      valid: false,
      reason: "unsupported_target"
    };
  }

  return {
    valid: true,
    reason: null
  };
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

function createDropPayload({
  dropId,
  event,
  target,
  text,
  files,
  dataTransfer,
  reason = null
}) {
  const types = getDataTransferTypes(dataTransfer);

  return {
    dropId,

    sourceType: SOURCE_TYPES.DROP,

    timestamp: now(),

    target: getSafeTargetMetadata(target),

    text,

    files,

    dataTransfer: {
      types,
      hasFiles: hasFiles(dataTransfer),
      hasText: hasText(dataTransfer),
      hasSupportedText: hasSupportedText(dataTransfer),
      hasHtml: hasHtml(dataTransfer)
    },

    reason,

    event: {
      type: event?.type || "drop"
    }
  };
}

function emitEvent(type, payload = {}) {
  const event = {
    type,
    sourceType: SOURCE_TYPES.DROP,
    timestamp: now(),
    ...payload
  };

  safeCallback(state.callbacks.onEvent, event);

  return event;
}

function getDefaultDecisionPayload(payload, action, reason = null) {
  return {
    ...payload,
    action,
    reason
  };
}

function executeInsertion(target, text) {
  if (!target || !text) {
    return false;
  }

  try {
    return Boolean(insertPasteText(target, text));
  } catch (error) {
    handleError(error, "insertDropText");
    return false;
  }
}

async function invokeWarningCallback(payload) {
  if (typeof state.callbacks.onWarning !== "function") {
    return normalizeAction(ACTIONS.BLOCK);
  }

  try {
    const result = await Promise.resolve(
      state.callbacks.onWarning(payload)
    );

    return normalizeAction(result);
  } catch (error) {
    handleError(error, "warningCallback");

    return ACTIONS.BLOCK;
  }
}

async function evaluateTextDrop({
  dropId,
  event,
  target,
  text,
  dataTransfer
}) {
  if (!text) {
    state.counters.rejectedDrops += 1;

    return ACTIONS.BLOCK;
  }

  if (!isClipboardTextWithinLimit(text)) {
    state.counters.oversizedTextDrops += 1;
    state.counters.blockedDrops += 1;

    const payload = createDropPayload({
      dropId,
      event,
      target,
      text: "",
      files: [],
      dataTransfer,
      reason: "text_too_large"
    });

    safeCallback(
      state.callbacks.onBlocked,
      getDefaultDecisionPayload(
        payload,
        ACTIONS.BLOCK,
        "text_too_large"
      )
    );

    emitEvent(EVENT_TYPES.ACTION_BLOCKED, {
      dropId,
      reason: "text_too_large"
    });

    return ACTIONS.BLOCK;
  }

  state.counters.textDrops += 1;

  const payload = createDropPayload({
    dropId,
    event,
    target,
    text,
    files: [],
    dataTransfer
  });

  emitEvent(EVENT_TYPES.DROP_DETECTED, {
    dropId,
    target: payload.target,
    hasText: true,
    hasFiles: false
  });

  if (typeof state.callbacks.onDrop !== "function") {
    const inserted = executeInsertion(target, text);

    if (inserted) {
      state.counters.allowedDrops += 1;

      safeCallback(
        state.callbacks.onAllowed,
        getDefaultDecisionPayload(
          {
            ...payload,
            text: ""
          },
          ACTIONS.ALLOW
        )
      );

      emitEvent(EVENT_TYPES.ACTION_ALLOWED, {
        dropId
      });

      return ACTIONS.ALLOW;
    }

    state.counters.blockedDrops += 1;

    return ACTIONS.BLOCK;
  }

  let decision;

  try {
    decision = await Promise.resolve(
      state.callbacks.onDrop(payload)
    );
  } catch (error) {
    handleError(error, "textDropCallback");
    decision = ACTIONS.BLOCK;
  }

  decision = normalizeAction(decision);

  if (decision === ACTIONS.ALLOW) {
    const inserted = executeInsertion(target, text);

    if (!inserted) {
      state.counters.blockedDrops += 1;

      safeCallback(
        state.callbacks.onBlocked,
        getDefaultDecisionPayload(
          {
            ...payload,
            text: ""
          },
          ACTIONS.BLOCK,
          "insertion_failed"
        )
      );

      emitEvent(EVENT_TYPES.ACTION_BLOCKED, {
        dropId,
        reason: "insertion_failed"
      });

      return ACTIONS.BLOCK;
    }

    state.counters.allowedDrops += 1;

    safeCallback(
      state.callbacks.onAllowed,
      getDefaultDecisionPayload(
        {
          ...payload,
          text: ""
        },
        ACTIONS.ALLOW
      )
    );

    emitEvent(EVENT_TYPES.ACTION_ALLOWED, {
      dropId
    });

    return ACTIONS.ALLOW;
  }

  if (decision === ACTIONS.WARN) {
    state.counters.warnedDrops += 1;

    const warningDecision = await invokeWarningCallback({
      ...payload,
      text: ""
    });

    if (warningDecision === ACTIONS.ALLOW) {
      const inserted = executeInsertion(target, text);

      if (!inserted) {
        state.counters.blockedDrops += 1;

        safeCallback(
          state.callbacks.onBlocked,
          getDefaultDecisionPayload(
            {
              ...payload,
              text: ""
            },
            ACTIONS.BLOCK,
            "insertion_failed"
          )
        );

        return ACTIONS.BLOCK;
      }

      state.counters.allowedDrops += 1;

      safeCallback(
        state.callbacks.onAllowed,
        getDefaultDecisionPayload(
          {
            ...payload,
            text: ""
          },
          ACTIONS.ALLOW,
          "warning_approved"
        )
      );

      emitEvent(EVENT_TYPES.ACTION_ALLOWED, {
        dropId,
        reason: "warning_approved"
      });

      return ACTIONS.ALLOW;
    }

    if (warningDecision === ACTIONS.MASK) {
      return executeMaskedTextDrop(
        dropId,
        event,
        target,
        text,
        dataTransfer
      );
    }

    state.counters.blockedDrops += 1;

    safeCallback(
      state.callbacks.onBlocked,
      getDefaultDecisionPayload(
        {
          ...payload,
          text: ""
        },
        ACTIONS.BLOCK,
        "warning_rejected"
      )
    );

    emitEvent(EVENT_TYPES.ACTION_BLOCKED, {
      dropId,
      reason: "warning_rejected"
    });

    return ACTIONS.BLOCK;
  }

  if (decision === ACTIONS.MASK) {
    return executeMaskedTextDrop(
      dropId,
      event,
      target,
      text,
      dataTransfer
    );
  }

  state.counters.blockedDrops += 1;

  safeCallback(
    state.callbacks.onBlocked,
    getDefaultDecisionPayload(
      {
        ...payload,
        text: ""
      },
      ACTIONS.BLOCK,
      "policy_block"
    )
  );

  emitEvent(EVENT_TYPES.ACTION_BLOCKED, {
    dropId,
    reason: "policy_block"
  });

  return ACTIONS.BLOCK;
}

function createMaskedText(text) {
  if (!text) {
    return "";
  }

  return String(text).replace(/\S+/g, "[REDACTED]");
}

async function executeMaskedTextDrop(
  dropId,
  event,
  target,
  text,
  dataTransfer
) {
  const maskedText = createMaskedText(text);

  if (!maskedText) {
    state.counters.blockedDrops += 1;
    return ACTIONS.BLOCK;
  }

  const inserted = executeInsertion(target, maskedText);

  const payload = createDropPayload({
    dropId,
    event,
    target,
    text: "",
    files: [],
    dataTransfer,
    reason: "masked"
  });

  if (!inserted) {
    state.counters.blockedDrops += 1;

    safeCallback(
      state.callbacks.onBlocked,
      getDefaultDecisionPayload(
        payload,
        ACTIONS.BLOCK,
        "masked_insertion_failed"
      )
    );

    emitEvent(EVENT_TYPES.ACTION_BLOCKED, {
      dropId,
      reason: "masked_insertion_failed"
    });

    return ACTIONS.BLOCK;
  }

  state.counters.maskedDrops += 1;

  safeCallback(
    state.callbacks.onMasked,
    getDefaultDecisionPayload(
      payload,
      ACTIONS.MASK
    )
  );

  emitEvent(EVENT_TYPES.ACTION_MASKED, {
    dropId
  });

  return ACTIONS.MASK;
}

async function evaluateFileDrop({
  dropId,
  event,
  target,
  files,
  dataTransfer
}) {
  state.counters.fileDrops += 1;

  const validation = validateDroppedFiles(files);

  const safeMetadata = getSafeFileMetadata(files);

  const payload = createDropPayload({
    dropId,
    event,
    target,
    text: "",
    files: safeMetadata,
    dataTransfer,
    reason: validation.reason
  });

  emitEvent(EVENT_TYPES.DROP_DETECTED, {
    dropId,
    target: payload.target,
    hasText: false,
    hasFiles: true,
    fileCount: safeMetadata.length
  });

  if (!validation.valid) {
    state.counters.oversizedFileDrops += 1;
    state.counters.blockedDrops += 1;

    safeCallback(
      state.callbacks.onBlocked,
      getDefaultDecisionPayload(
        payload,
        ACTIONS.BLOCK,
        validation.reason
      )
    );

    emitEvent(EVENT_TYPES.ACTION_BLOCKED, {
      dropId,
      reason: validation.reason
    });

    return ACTIONS.BLOCK;
  }

  if (!state.config.fileScan.enabled) {
    return handleFileDropWithoutScanning({
      dropId,
      event,
      target,
      files,
      dataTransfer,
      payload
    });
  }

  if (typeof state.callbacks.onFileDrop !== "function") {
    state.counters.blockedDrops += 1;

    safeCallback(
      state.callbacks.onBlocked,
      getDefaultDecisionPayload(
        payload,
        ACTIONS.BLOCK,
        "file_scanner_not_ready"
      )
    );

    emitEvent(EVENT_TYPES.ACTION_BLOCKED, {
      dropId,
      reason: "file_scanner_not_ready"
    });

    return ACTIONS.BLOCK;
  }

  let decision;

  try {
    /*
     * IMPORTANT:
     *
     * The actual File objects remain inside the content-script context.
     * Do not pass this payload directly to chrome.runtime.sendMessage().
     *
     * upload-monitor.js will own file reading and local scanning.
     */
    decision = await Promise.resolve(
      state.callbacks.onFileDrop({
        ...payload,
        files
      })
    );
  } catch (error) {
    handleError(error, "fileDropCallback");
    decision = ACTIONS.BLOCK;
  }

  decision = normalizeAction(decision);

  if (decision === ACTIONS.ALLOW) {
    state.counters.allowedDrops += 1;

    safeCallback(
      state.callbacks.onAllowed,
      getDefaultDecisionPayload(
        payload,
        ACTIONS.ALLOW
      )
    );

    emitEvent(EVENT_TYPES.ACTION_ALLOWED, {
      dropId
    });

    return ACTIONS.ALLOW;
  }

  if (decision === ACTIONS.WARN) {
    state.counters.warnedDrops += 1;

    const warningDecision = await invokeWarningCallback(payload);

    if (warningDecision === ACTIONS.ALLOW) {
      state.counters.allowedDrops += 1;

      safeCallback(
        state.callbacks.onAllowed,
        getDefaultDecisionPayload(
          payload,
          ACTIONS.ALLOW,
          "warning_approved"
        )
      );

      emitEvent(EVENT_TYPES.ACTION_ALLOWED, {
        dropId,
        reason: "warning_approved"
      });

      return ACTIONS.ALLOW;
    }

    if (warningDecision === ACTIONS.BLOCK) {
      state.counters.blockedDrops += 1;

      safeCallback(
        state.callbacks.onBlocked,
        getDefaultDecisionPayload(
          payload,
          ACTIONS.BLOCK,
          "warning_rejected"
        )
      );

      emitEvent(EVENT_TYPES.ACTION_BLOCKED, {
        dropId,
        reason: "warning_rejected"
      });

      return ACTIONS.BLOCK;
    }

    if (warningDecision === ACTIONS.MASK) {
      /*
       * File masking is deliberately not performed here.
       *
       * A file is an opaque object and cannot safely be transformed
       * without the scanner/upload pipeline deciding how it should be
       * sanitized. upload-monitor.js will handle that later.
       */
      state.counters.blockedDrops += 1;

      safeCallback(
        state.callbacks.onBlocked,
        getDefaultDecisionPayload(
          payload,
          ACTIONS.BLOCK,
          "file_masking_not_supported_at_drop_boundary"
        )
      );

      emitEvent(EVENT_TYPES.ACTION_BLOCKED, {
        dropId,
        reason: "file_masking_not_supported_at_drop_boundary"
      });

      return ACTIONS.BLOCK;
    }

    state.counters.blockedDrops += 1;

    return ACTIONS.BLOCK;
  }

  if (decision === ACTIONS.MASK) {
    /*
     * Never pretend that a file has been masked.
     *
     * The file must be transformed by the upload/scanning pipeline.
     */
    state.counters.blockedDrops += 1;

    safeCallback(
      state.callbacks.onBlocked,
      getDefaultDecisionPayload(
        payload,
        ACTIONS.BLOCK,
        "file_masking_requires_upload_pipeline"
      )
    );

    emitEvent(EVENT_TYPES.ACTION_BLOCKED, {
      dropId,
      reason: "file_masking_requires_upload_pipeline"
    });

    return ACTIONS.BLOCK;
  }

  state.counters.blockedDrops += 1;

  safeCallback(
    state.callbacks.onBlocked,
    getDefaultDecisionPayload(
      payload,
      ACTIONS.BLOCK,
      "policy_block"
    )
  );

  emitEvent(EVENT_TYPES.ACTION_BLOCKED, {
    dropId,
    reason: "policy_block"
  });

  return ACTIONS.BLOCK;
}

async function handleFileDropWithoutScanning({
  dropId,
  event,
  target,
  files,
  dataTransfer,
  payload
}) {
  if (typeof state.callbacks.onFileDrop === "function") {
    try {
      const decision = normalizeAction(
        await Promise.resolve(
          state.callbacks.onFileDrop({
            ...payload,
            files,
            scanningDisabled: true
          })
        )
      );

      if (decision === ACTIONS.ALLOW) {
        state.counters.allowedDrops += 1;

        safeCallback(
          state.callbacks.onAllowed,
          getDefaultDecisionPayload(
            payload,
            ACTIONS.ALLOW
          )
        );

        emitEvent(EVENT_TYPES.ACTION_ALLOWED, {
          dropId
        });

        return ACTIONS.ALLOW;
      }

      if (decision === ACTIONS.WARN) {
        state.counters.warnedDrops += 1;

        const warningDecision =
          await invokeWarningCallback(payload);

        if (warningDecision === ACTIONS.ALLOW) {
          state.counters.allowedDrops += 1;

          safeCallback(
            state.callbacks.onAllowed,
            getDefaultDecisionPayload(
              payload,
              ACTIONS.ALLOW,
              "warning_approved"
            )
          );

          return ACTIONS.ALLOW;
        }
      }
    } catch (error) {
      handleError(error, "fileDropWithoutScanning");
    }
  }

  /*
   * If no explicit local file handler exists, fail closed.
   *
   * A future upload-monitor.js will become the authoritative handler
   * for file drops.
   */
  state.counters.blockedDrops += 1;

  safeCallback(
    state.callbacks.onBlocked,
    getDefaultDecisionPayload(
      payload,
      ACTIONS.BLOCK,
      "file_handler_not_ready"
    )
  );

  emitEvent(EVENT_TYPES.ACTION_BLOCKED, {
    dropId,
    reason: "file_handler_not_ready"
  });

  return ACTIONS.BLOCK;
}

function shouldProcessDrop() {
  if (!state.initialized || state.destroyed) {
    return false;
  }

  if (!state.config.enabled) {
    return false;
  }

  if (state.config.mode === "disabled") {
    return false;
  }

  if (!state.config.scanDragDrop) {
    return false;
  }

  return true;
}

function isProtectedTarget(target) {
  const editable = findEditableTarget(target);

  if (!editable) {
    return false;
  }

  const validation = validateDropTarget(editable);

  return validation.valid;
}

function preventDropEvent(event) {
  if (!event) {
    return;
  }

  try {
    event.preventDefault();
    event.stopPropagation();
  } catch (error) {
    handleError(error, "preventDropEvent");
  }
}

function allowDropEvent(event) {
  if (!event) {
    return;
  }

  try {
    event.preventDefault();
  } catch (error) {
    handleError(error, "allowDropEvent");
  }
}

function handleDragEnter(event) {
  if (!shouldProcessDrop()) {
    return;
  }

  state.counters.dragEnter += 1;

  const target = findEditableTarget(event.target);

  if (!isProtectedTarget(target)) {
    return;
  }

  state.dragDepth += 1;
  state.activeDragTarget = target;

  emitEvent(EVENT_TYPES.INPUT_DETECTED, {
    phase: "dragenter",
    target: getSafeTargetMetadata(target)
  });
}

function handleDragOver(event) {
  if (!shouldProcessDrop()) {
    return;
  }

  state.counters.dragOver += 1;

  const target = findEditableTarget(event.target);

  if (!isProtectedTarget(target)) {
    return;
  }

  /*
   * Calling preventDefault() during dragover tells the browser that
   * the drop target accepts the operation.
   *
   * We intentionally do not insert or read the payload here.
   */
  allowDropEvent(event);

  state.activeDragTarget = target;
}

function handleDragLeave(event) {
  if (!shouldProcessDrop()) {
    return;
  }

  state.counters.dragLeave += 1;

  const target = findEditableTarget(event.target);

  if (!target || target !== state.activeDragTarget) {
    return;
  }

  state.dragDepth = Math.max(0, state.dragDepth - 1);

  if (state.dragDepth === 0) {
    state.activeDragTarget = null;
  }
}

async function handleDrop(event) {
  if (!shouldProcessDrop()) {
    return;
  }

  if (state.processingDrop) {
    preventDropEvent(event);
    state.counters.blockedDrops += 1;

    emitEvent(EVENT_TYPES.ACTION_BLOCKED, {
      reason: "drop_already_processing"
    });

    return;
  }

  const target = findEditableTarget(event.target);

  if (!isProtectedTarget(target)) {
    return;
  }

  const dataTransfer = event.dataTransfer;

  if (!dataTransfer) {
    preventDropEvent(event);

    state.counters.blockedDrops += 1;

    emitEvent(EVENT_TYPES.ACTION_BLOCKED, {
      reason: "missing_data_transfer"
    });

    return;
  }

  const dropId = createDropId();

  state.pendingDropId = dropId;
  state.processingDrop = true;
  state.lastDropTarget = target;
  state.dragDepth = 0;
  state.activeDragTarget = null;

  /*
   * The native drop must be cancelled before asynchronous scanning.
   * Otherwise the browser may insert the unscanned content immediately.
   */
  preventDropEvent(event);

  state.counters.drop += 1;

  try {
    const containsFiles = hasFiles(dataTransfer);
    const containsSupportedText = hasSupportedText(dataTransfer);
    const containsHtmlOnly = hasHtml(dataTransfer) && !containsSupportedText;

    if (containsFiles) {
      const files = getDroppedFiles(dataTransfer);

      if (files.length === 0) {
        state.counters.blockedDrops += 1;

        emitEvent(EVENT_TYPES.ACTION_BLOCKED, {
          dropId,
          reason: "file_drop_without_files"
        });

        return;
      }

      await evaluateFileDrop({
        dropId,
        event,
        target,
        files,
        dataTransfer
      });

      return;
    }

    if (containsSupportedText) {
      const text = extractPlainText(dataTransfer);

      await evaluateTextDrop({
        dropId,
        event,
        target,
        text,
        dataTransfer
      });

      return;
    }

    /*
     * Some browsers/applications expose text through the generic
     * "text" type instead of "text/plain".
     */
    if (hasText(dataTransfer)) {
      const text = extractPlainText(dataTransfer);

      if (text) {
        await evaluateTextDrop({
          dropId,
          event,
          target,
          text,
          dataTransfer
        });

        return;
      }

      const uriList = extractUriList(dataTransfer);

      if (uriList) {
        await evaluateTextDrop({
          dropId,
          event,
          target,
          text: uriList,
          dataTransfer
        });

        return;
      }
    }

    if (containsHtmlOnly) {
      state.counters.unsupportedDrops += 1;
      state.counters.blockedDrops += 1;

      const payload = createDropPayload({
        dropId,
        event,
        target,
        text: "",
        files: [],
        dataTransfer,
        reason: "html_only_drop"
      });

      safeCallback(
        state.callbacks.onBlocked,
        getDefaultDecisionPayload(
          payload,
          ACTIONS.BLOCK,
          "html_only_drop"
        )
      );

      emitEvent(EVENT_TYPES.ACTION_BLOCKED, {
        dropId,
        reason: "html_only_drop"
      });

      return;
    }

    state.counters.unsupportedDrops += 1;
    state.counters.blockedDrops += 1;

    const payload = createDropPayload({
      dropId,
      event,
      target,
      text: "",
      files: [],
      dataTransfer,
      reason: "unsupported_drop_type"
    });

    safeCallback(
      state.callbacks.onBlocked,
      getDefaultDecisionPayload(
        payload,
        ACTIONS.BLOCK,
        "unsupported_drop_type"
      )
    );

    emitEvent(EVENT_TYPES.ACTION_BLOCKED, {
      dropId,
      reason: "unsupported_drop_type"
    });
  } catch (error) {
    state.counters.errors += 1;
    state.counters.blockedDrops += 1;

    handleError(error, "handleDrop");

    emitEvent(EVENT_TYPES.ACTION_BLOCKED, {
      dropId,
      reason: "drop_processing_error"
    });
  } finally {
    state.processingDrop = false;
    state.pendingDropId = null;
  }
}

function addListener(target, eventName, handler, options = true) {
  if (!target || typeof target.addEventListener !== "function") {
    return;
  }

  target.addEventListener(eventName, handler, options);

  state.listeners.push({
    target,
    eventName,
    handler,
    options
  });
}

function removeListeners() {
  for (const listener of state.listeners) {
    try {
      listener.target.removeEventListener(
        listener.eventName,
        listener.handler,
        listener.options
      );
    } catch {
      // Ignore cleanup failures.
    }
  }

  state.listeners = [];
}

function resetDragState() {
  state.dragDepth = 0;
  state.activeDragTarget = null;
  state.lastDropTarget = null;
  state.processingDrop = false;
  state.pendingDropId = null;
}

function installListeners() {
  removeListeners();

  addListener(
    document,
    "dragenter",
    handleDragEnter,
    true
  );

  addListener(
    document,
    "dragover",
    handleDragOver,
    true
  );

  addListener(
    document,
    "dragleave",
    handleDragLeave,
    true
  );

  addListener(
    document,
    "drop",
    handleDrop,
    true
  );
}

function mergeConfig(config = {}) {
  if (!isObject(config)) {
    return;
  }

  if (typeof config.enabled === "boolean") {
    state.config.enabled = config.enabled;
  }

  if (typeof config.scanDragDrop === "boolean") {
    state.config.scanDragDrop = config.scanDragDrop;
  }

  if (typeof config.mode === "string") {
    state.config.mode = config.mode;
  }

  if (typeof config.defaultAction === "string") {
    state.config.defaultAction = normalizeAction(
      config.defaultAction
    );
  }

  if (isObject(config.fileScan)) {
    state.config.fileScan = {
      ...state.config.fileScan,
      ...config.fileScan
    };
  }
}

function setCallbacks(callbacks = {}) {
  if (!isObject(callbacks)) {
    return;
  }

  const supportedCallbacks = [
    "onDrop",
    "onFileDrop",
    "onWarning",
    "onBlocked",
    "onAllowed",
    "onMasked",
    "onEvent",
    "onError"
  ];

  for (const callbackName of supportedCallbacks) {
    if (
      callbacks[callbackName] === null ||
      typeof callbacks[callbackName] === "function"
    ) {
      state.callbacks[callbackName] =
        callbacks[callbackName];
    }
  }
}

function initialize(options = {}) {
  if (state.initialized && !state.destroyed) {
    if (options.config) {
      mergeConfig(options.config);
    }

    if (options.callbacks) {
      setCallbacks(options.callbacks);
    }

    return getDropMonitorDiagnostics();
  }

  state.destroyed = false;

  mergeConfig(options.config || {});
  setCallbacks(options.callbacks || {});

  installListeners();

  state.initialized = true;

  emitEvent(EVENT_TYPES.CONTENT_READY, {
    component: "drop-monitor"
  });

  return getDropMonitorDiagnostics();
}

function destroy() {
  removeListeners();
  resetDragState();

  state.initialized = false;
  state.destroyed = true;

  for (const key of Object.keys(state.callbacks)) {
    state.callbacks[key] = null;
  }
}

function updateConfig(config = {}) {
  mergeConfig(config);

  if (state.initialized && !state.destroyed) {
    installListeners();
  }

  return getDropMonitorDiagnostics();
}

function getDropMonitorConfig() {
  return {
    enabled: state.config.enabled,
    scanDragDrop: state.config.scanDragDrop,
    mode: state.config.mode,
    defaultAction: state.config.defaultAction,
    fileScan: {
      ...state.config.fileScan
    }
  };
}

function getDropMonitorDiagnostics() {
  return {
    initialized: state.initialized,
    destroyed: state.destroyed,

    config: getDropMonitorConfig(),

    dragState: {
      dragDepth: state.dragDepth,
      hasActiveDragTarget: Boolean(
        state.activeDragTarget
      ),
      hasLastDropTarget: Boolean(
        state.lastDropTarget
      ),
      processingDrop: state.processingDrop,
      hasPendingDrop: Boolean(state.pendingDropId)
    },

    counters: {
      ...state.counters
    },

    listeners: state.listeners.length,

    callbackState: {
      onDrop: typeof state.callbacks.onDrop === "function",
      onFileDrop:
        typeof state.callbacks.onFileDrop === "function",
      onWarning:
        typeof state.callbacks.onWarning === "function",
      onBlocked:
        typeof state.callbacks.onBlocked === "function",
      onAllowed:
        typeof state.callbacks.onAllowed === "function",
      onMasked:
        typeof state.callbacks.onMasked === "function",
      onEvent:
        typeof state.callbacks.onEvent === "function",
      onError:
        typeof state.callbacks.onError === "function"
    }
  };
}

function getDropState() {
  return {
    dragDepth: state.dragDepth,
    processingDrop: state.processingDrop,
    pendingDropId: state.pendingDropId,
    hasActiveDragTarget: Boolean(
      state.activeDragTarget
    ),
    hasLastDropTarget: Boolean(
      state.lastDropTarget
    )
  };
}

function isDropMonitorInitialized() {
  return state.initialized && !state.destroyed;
}

function isProcessingDrop() {
  return state.processingDrop;
}

function isProtectedDropTarget(target) {
  return isProtectedTarget(target);
}

function getCurrentDropTarget() {
  if (
    state.lastDropTarget &&
    isConnectedElement(state.lastDropTarget)
  ) {
    return state.lastDropTarget;
  }

  if (
    state.activeDragTarget &&
    isConnectedElement(state.activeDragTarget)
  ) {
    return state.activeDragTarget;
  }

  return null;
}

function getDropCapabilities() {
  return {
    text: true,
    files: true,
    plainTextOnly: true,
    htmlDropInsertion: false,
    localProcessing: true,
    backgroundRawPayloadTransfer: false
  };
}

export {
  initialize,
  destroy,

  updateConfig,
  setCallbacks,

  getDropMonitorConfig,
  getDropMonitorDiagnostics,
  getDropState,
  getDropCapabilities,

  isDropMonitorInitialized,
  isProcessingDrop,
  isProtectedDropTarget,
  getCurrentDropTarget,

  getDataTransferTypes,
  hasFiles,
  hasText,
  hasSupportedText,
  hasHtml,

  extractPlainText,
  extractUriList,
  getDroppedFiles,

  getFileMetadata,
  getSafeFileMetadata,

  validateDroppedFiles,
  validateDropTarget,

  findEditableTarget,
  isEditableTarget
};
