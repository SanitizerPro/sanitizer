/**
 * SanitizerPro
 * Submit Monitor
 *
 * Security boundary:
 * - Form values remain inside the content-script context.
 * - No form values are sent to the service worker.
 * - No form values are persisted.
 * - Submission approval is one-time only.
 * - Failed protection callbacks fail closed.
 *
 * Responsibilities:
 * - Intercept HTML form submissions.
 * - Collect form data locally.
 * - Detect submitters.
 * - Support dynamically created forms.
 * - Support Enter-key submissions.
 * - Allow content.js to scan/evaluate the submission.
 * - Continue approved submissions exactly once.
 * - Prevent recursive interception caused by requestSubmit().
 */

import {
  SCAN_LIMITS,
  PROTECTION_DEFAULTS,
  ACTIONS,
  SOURCE_TYPES,
} from "../config/defaults.js";

import {
  EVENT_TYPES,
} from "../config/constants.js";

const MONITOR_VERSION = "1.1.0";

const DEFAULT_CONFIG = Object.freeze({
  enabled: true,
  scanSubmit: true,
  scanTextFields: true,
  scanTextareas: true,
  scanContentEditable: true,
  includeButtonText: false,
  includeLabels: true,
  includeNames: false,
  includeNonTextControls: false,
  interceptEnterKey: true,
  interceptClickSubmit: true,
  dynamicForms: true,
  maximumFields: 200,
  maximumFieldCharacters: 50000,
  maximumCombinedCharacters:
    SCAN_LIMITS?.maxTextCharacters ??
    250000,
  approvalTimeoutMs: 5000,
  operationTimeoutMs: 10000,
});

const state = {
  initialized: false,
  destroyed: false,

  config: {
    ...DEFAULT_CONFIG,
  },

  forms: new Set(),
  trackedSubmitters: new WeakMap(),

  /*
   * One-time approval records.
   *
   * WeakMap<Form, ApprovalRecord>
   *
   * The record is consumed by the next intercepted submission and cannot
   * authorize later submissions.
   */
  approvals: new WeakMap(),

  /*
   * requestSubmit()/submit() continuation guards.
   *
   * WeakSet is used because DOM form objects must never be persisted.
   */
  continuingForms: new WeakSet(),

  /*
   * Forms currently being processed by the protection callback.
   */
  pendingForms: new WeakSet(),

  /*
   * Prevent duplicate processing when multiple browser events describe
   * the same submission attempt.
   */
  pendingOperations: new WeakMap(),

  activeSubmitter: new WeakMap(),

  observers: new Set(),

  eventHandlers: {
    submit: null,
    click: null,
    keydown: null,
  },

  callbacks: {
    onSubmit: null,
    onWarning: null,
    onError: null,
    onEvent: null,
  },

  stats: {
    submitAttempts: 0,
    submissionsInspected: 0,
    submissionsAllowed: 0,
    submissionsWarned: 0,
    submissionsMasked: 0,
    submissionsBlocked: 0,
    submissionsFailed: 0,
    submissionsApproved: 0,
    submissionsContinued: 0,
    recursiveSubmissionsPrevented: 0,
    emptySubmissions: 0,
    oversizedSubmissions: 0,
    unsupportedSubmissions: 0,
    formsTracked: 0,
    submitterClicks: 0,
    enterSubmissions: 0,
    callbackTimeouts: 0,
  },

  lastEventAt: 0,
};

/* -------------------------------------------------------------------------- */
/* Initialization                                                            */
/* -------------------------------------------------------------------------- */

function initializeSubmitMonitor(options = {}) {
  if (state.initialized && !state.destroyed) {
    return getSubmitMonitorStatus();
  }

  state.destroyed = false;

  state.config = normalizeConfig(
    options.config ??
      options.submitConfig ??
      DEFAULT_CONFIG,
  );

  state.callbacks.onSubmit =
    typeof options.onSubmit === "function"
      ? options.onSubmit
      : null;

  state.callbacks.onWarning =
    typeof options.onWarning === "function"
      ? options.onWarning
      : null;

  state.callbacks.onError =
    typeof options.onError === "function"
      ? options.onError
      : null;

  state.callbacks.onEvent =
    typeof options.onEvent === "function"
      ? options.onEvent
      : null;

  if (!state.config.enabled) {
    state.initialized = true;
    return getSubmitMonitorStatus();
  }

  bindEventListeners();

  if (state.config.dynamicForms) {
    initializeFormObserver();
  }

  discoverForms();

  state.initialized = true;

  emitEvent(
    EVENT_TYPES.INIT,
    {
      sourceType: SOURCE_TYPES.SUBMIT,
    },
  );

  return getSubmitMonitorStatus();
}

/* -------------------------------------------------------------------------- */
/* Configuration                                                              */
/* -------------------------------------------------------------------------- */

function normalizeConfig(config = {}) {
  const merged = {
    ...DEFAULT_CONFIG,
    ...config,
  };

  if (
    config &&
    typeof config.submit === "object" &&
    config.submit !== null
  ) {
    Object.assign(
      merged,
      config.submit,
    );
  }

  merged.enabled =
    merged.enabled !== false;

  merged.scanSubmit =
    merged.scanSubmit !== false;

  merged.scanTextFields =
    merged.scanTextFields !== false;

  merged.scanTextareas =
    merged.scanTextareas !== false;

  merged.scanContentEditable =
    merged.scanContentEditable !== false;

  merged.includeButtonText =
    merged.includeButtonText === true;

  merged.includeLabels =
    merged.includeLabels !== false;

  merged.includeNames =
    merged.includeNames === true;

  merged.includeNonTextControls =
    merged.includeNonTextControls === true;

  merged.interceptEnterKey =
    merged.interceptEnterKey !== false;

  merged.interceptClickSubmit =
    merged.interceptClickSubmit !== false;

  merged.dynamicForms =
    merged.dynamicForms !== false;

  merged.maximumFields =
    clampInteger(
      merged.maximumFields,
      1,
      1000,
      DEFAULT_CONFIG.maximumFields,
    );

  merged.maximumFieldCharacters =
    clampInteger(
      merged.maximumFieldCharacters,
      100,
      SCAN_LIMITS?.maxTextCharacters ??
        250000,
      DEFAULT_CONFIG.maximumFieldCharacters,
    );

  merged.maximumCombinedCharacters =
    clampInteger(
      merged.maximumCombinedCharacters,
      100,
      SCAN_LIMITS?.maxTextCharacters ??
        250000,
      DEFAULT_CONFIG.maximumCombinedCharacters,
    );

  merged.approvalTimeoutMs =
    clampInteger(
      merged.approvalTimeoutMs,
      500,
      30000,
      DEFAULT_CONFIG.approvalTimeoutMs,
    );

  merged.operationTimeoutMs =
    clampInteger(
      merged.operationTimeoutMs,
      1000,
      30000,
      DEFAULT_CONFIG.operationTimeoutMs,
    );

  return merged;
}

/* -------------------------------------------------------------------------- */
/* Event listeners                                                            */
/* -------------------------------------------------------------------------- */

function bindEventListeners() {
  if (
    !state.eventHandlers.submit
  ) {
    state.eventHandlers.submit =
      handleSubmitEvent;

    document.addEventListener(
      "submit",
      state.eventHandlers.submit,
      true,
    );
  }

  if (
    state.config.interceptClickSubmit &&
    !state.eventHandlers.click
  ) {
    state.eventHandlers.click =
      handleClickEvent;

    document.addEventListener(
      "click",
      state.eventHandlers.click,
      true,
    );
  }

  if (
    state.config.interceptEnterKey &&
    !state.eventHandlers.keydown
  ) {
    state.eventHandlers.keydown =
      handleKeydownEvent;

    document.addEventListener(
      "keydown",
      state.eventHandlers.keydown,
      true,
    );
  }
}

function unbindEventListeners() {
  if (state.eventHandlers.submit) {
    document.removeEventListener(
      "submit",
      state.eventHandlers.submit,
      true,
    );

    state.eventHandlers.submit = null;
  }

  if (state.eventHandlers.click) {
    document.removeEventListener(
      "click",
      state.eventHandlers.click,
      true,
    );

    state.eventHandlers.click = null;
  }

  if (state.eventHandlers.keydown) {
    document.removeEventListener(
      "keydown",
      state.eventHandlers.keydown,
      true,
    );

    state.eventHandlers.keydown = null;
  }
}

/* -------------------------------------------------------------------------- */
/* Form discovery                                                             */
/* -------------------------------------------------------------------------- */

function discoverForms(root = document) {
  if (
    !root ||
    typeof root.querySelectorAll !==
      "function"
  ) {
    return;
  }

  let forms = [];

  try {
    forms =
      root.querySelectorAll("form");
  } catch {
    return;
  }

  for (const form of forms) {
    trackForm(form);
  }
}

function trackForm(form) {
  if (!isValidForm(form)) {
    return false;
  }

  if (state.forms.has(form)) {
    return true;
  }

  state.forms.add(form);

  state.stats.formsTracked += 1;

  return true;
}

function untrackForm(form) {
  if (!form) {
    return;
  }

  state.forms.delete(form);

  clearApproval(form);
  state.pendingForms.delete(form);
}

/* -------------------------------------------------------------------------- */
/* Mutation observer                                                          */
/* -------------------------------------------------------------------------- */

function initializeFormObserver() {
  if (
    typeof MutationObserver ===
    "undefined"
  ) {
    return;
  }

  const observer =
    new MutationObserver(
      handleMutations,
    );

  try {
    observer.observe(
      document.documentElement ||
        document,
      {
        childList: true,
        subtree: true,
      },
    );

    state.observers.add(observer);
  } catch (error) {
    reportError(
      error,
      "Unable to initialize form observer.",
    );
  }
}

function handleMutations(
  mutations,
) {
  if (state.destroyed) {
    return;
  }

  for (const mutation of mutations) {
    if (
      mutation.type !==
      "childList"
    ) {
      continue;
    }

    for (const node of mutation.addedNodes) {
      if (
        !isElementNode(node)
      ) {
        continue;
      }

      if (
        node.matches?.("form")
      ) {
        trackForm(node);
      }

      discoverForms(node);
    }

    for (const node of mutation.removedNodes) {
      if (
        !isElementNode(node)
      ) {
        continue;
      }

      if (
        node.matches?.("form")
      ) {
        untrackForm(node);
      }

      cleanupDisconnectedForms();
    }
  }
}

function cleanupDisconnectedForms() {
  for (const form of state.forms) {
    if (
      !isConnectedElement(form)
    ) {
      untrackForm(form);
    }
  }
}

/* -------------------------------------------------------------------------- */
/* Submit event                                                               */
/* -------------------------------------------------------------------------- */

function handleSubmitEvent(
  event,
) {
  if (
    state.destroyed ||
    !state.config.enabled ||
    !state.config.scanSubmit
  ) {
    return;
  }

  const form = getFormFromSubmitEvent(
    event,
  );

  if (!form) {
    return;
  }

  state.stats.submitAttempts += 1;
  state.lastEventAt = Date.now();

  trackForm(form);

  /*
   * If this submit was generated by SanitizerPro after an approved
   * decision, consume the approval and allow exactly this submission.
   */
  if (
    state.continuingForms.has(form)
  ) {
    state.stats.submissionsContinued += 1;

    /*
     * Remove the continuation marker immediately.
     *
     * This prevents a second future submit from bypassing scanning.
     */
    state.continuingForms.delete(form);

    clearApproval(form);

    return;
  }

  /*
   * A one-time approval may have been registered by content.js after
   * the user selected ALLOW or MASK.
   */
  const approval =
    consumeApproval(form);

  if (approval) {
    state.stats.submissionsApproved += 1;

    /*
     * We intentionally do not preventDefault().
     * This allows the browser/application to perform the approved
     * submission normally.
     */
    return;
  }

  /*
   * If a submission is already being inspected, do not launch another
   * concurrent scan for the same form.
   */
  if (
    state.pendingForms.has(form)
  ) {
    event.preventDefault();
    event.stopImmediatePropagation();

    state.stats.submissionsBlocked += 1;

    reportEvent(
      EVENT_TYPES.ACTION_BLOCKED,
      {
        sourceType:
          SOURCE_TYPES.SUBMIT,
        reason:
          "A submission scan is already in progress.",
      },
    );

    return;
  }

  /*
   * preventDefault() must happen synchronously before any await.
   */
  event.preventDefault();
  event.stopImmediatePropagation();

  const submitter =
    getSubmitterFromEvent(
      event,
      form,
    );

  if (submitter) {
    state.activeSubmitter.set(
      form,
      submitter,
    );
  }

  const snapshot =
    collectFormSnapshot(
      form,
      submitter,
    );

  if (
    snapshot.empty
  ) {
    state.stats.emptySubmissions += 1;

    /*
     * Empty submissions do not contain user data.
     * Continue the original submission safely.
     */
    continueApprovedSubmission(
      form,
      submitter,
      {
        reason:
          "No scannable content was found.",
      },
    );

    return;
  }

  if (
    snapshot.oversized
  ) {
    state.stats.oversizedSubmissions += 1;

    /*
     * Do not permit oversized content to bypass protection.
     */
    blockSubmission(
      form,
      submitter,
      {
        reason:
          "The submission exceeds SanitizerPro's local scanning limit.",
        reasonCode:
          "SUBMISSION_TOO_LARGE",
      },
    );

    return;
  }

  state.pendingForms.add(form);
  state.stats.submissionsInspected += 1;

  processSubmission(
    form,
    submitter,
    snapshot,
  );
}

/* -------------------------------------------------------------------------- */
/* Click handling                                                             */
/* -------------------------------------------------------------------------- */

function handleClickEvent(
  event,
) {
  if (
    state.destroyed ||
    !state.config.enabled
  ) {
    return;
  }

  const target =
    getEventElement(
      event,
    );

  if (!target) {
    return;
  }

  const submitter =
    findSubmitterElement(
      target,
    );

  if (!submitter) {
    return;
  }

  const form =
    getFormForElement(
      submitter,
    );

  if (!form) {
    return;
  }

  trackForm(form);

  state.trackedSubmitters =
    state.trackedSubmitters ||
    new WeakMap();

  state.trackedSubmitters.set(
    form,
    submitter,
  );

  state.activeSubmitter.set(
    form,
    submitter,
  );

  state.stats.submitterClicks += 1;

  reportEvent(
    EVENT_TYPES.SEND_DETECTED,
    {
      sourceType:
        SOURCE_TYPES.SUBMIT,
    },
  );
}

/* -------------------------------------------------------------------------- */
/* Enter-key handling                                                         */
/* -------------------------------------------------------------------------- */

function handleKeydownEvent(
  event,
) {
  if (
    state.destroyed ||
    !state.config.enabled ||
    !state.config.interceptEnterKey
  ) {
    return;
  }

  if (
    event.defaultPrevented ||
    event.key !== "Enter" ||
    event.isComposing
  ) {
    return;
  }

  const target =
    getEventElement(
      event,
    );

  if (!target) {
    return;
  }

  if (
    isTextarea(target) &&
    !event.ctrlKey &&
    !event.metaKey
  ) {
    /*
     * Enter in a textarea normally means newline.
     * Do not treat it as a submission unless the site explicitly
     * handles Ctrl+Enter or another submit mechanism.
     */
    return;
  }

  const form =
    getFormForElement(
      target,
    );

  if (!form) {
    return;
  }

  const submitter =
    getSubmitterForForm(
      form,
    );

  if (submitter) {
    state.activeSubmitter.set(
      form,
      submitter,
    );
  }

  state.stats.enterSubmissions += 1;

  /*
   * We do not prevent Enter here.
   *
   * The browser's submit event is the authoritative interception point.
   */
}

/* -------------------------------------------------------------------------- */
/* Submission processing                                                      */
/* -------------------------------------------------------------------------- */

async function processSubmission(
  form,
  submitter,
  snapshot,
) {
  try {
    if (
      typeof state.callbacks.onSubmit !==
      "function"
    ) {
      /*
       * Security boundary:
       * no protection callback means we cannot verify the data.
       * Fail closed.
       */
      blockSubmission(
        form,
        submitter,
        {
          reason:
            "SanitizerPro protection is not available.",
          reasonCode:
            "PROTECTION_CALLBACK_UNAVAILABLE",
        },
      );

      return;
    }

    const payload = createLocalSubmissionPayload(
      form,
      submitter,
      snapshot,
    );

    let result;

    try {
      result =
        await runWithTimeout(
          Promise.resolve(
            state.callbacks.onSubmit(
              payload,
            ),
          ),
          state.config.operationTimeoutMs,
          "SUBMIT_PROTECTION_TIMEOUT",
        );
    } catch (error) {
      if (
        error?.code ===
        "SUBMIT_PROTECTION_TIMEOUT"
      ) {
        state.stats.callbackTimeouts += 1;
      }

      throw error;
    }

    await handleProtectionResult(
      form,
      submitter,
      snapshot,
      result,
    );
  } catch (error) {
    state.stats.submissionsFailed += 1;

    reportError(
      error,
      "Submission protection failed.",
    );

    blockSubmission(
      form,
      submitter,
      {
        reason:
          "SanitizerPro could not safely inspect this submission.",
        reasonCode:
          error?.code ??
          "SUBMISSION_PROTECTION_FAILED",
      },
    );
  } finally {
    state.pendingForms.delete(form);
  }
}

async function handleProtectionResult(
  form,
  submitter,
  snapshot,
  result,
) {
  const action =
    normalizeAction(
      result?.action,
    );

  switch (action) {
    case ACTIONS.ALLOW:
      state.stats.submissionsAllowed += 1;

      approveAndContinue(
        form,
        submitter,
        {
          mode: "allow",
          result,
        },
      );

      return;

    case ACTIONS.MASK:
      state.stats.submissionsMasked += 1;

      await handleMaskedResult(
        form,
        submitter,
        snapshot,
        result,
      );

      return;

    case ACTIONS.WARN:
      state.stats.submissionsWarned += 1;

      await handleWarningResult(
        form,
        submitter,
        snapshot,
        result,
      );

      return;

    case ACTIONS.BLOCK:
      state.stats.submissionsBlocked += 1;

      blockSubmission(
        form,
        submitter,
        {
          reason:
            result?.reason ??
            "SanitizerPro blocked this submission.",
          reasonCode:
            result?.reasonCode ??
            "SENSITIVE_DATA_DETECTED",
          result,
        },
      );

      return;

    default:
      state.stats.submissionsBlocked += 1;

      blockSubmission(
        form,
        submitter,
        {
          reason:
            "Unknown SanitizerPro action.",
          reasonCode:
            "UNKNOWN_PROTECTION_ACTION",
          result,
        },
      );
  }
}

/* -------------------------------------------------------------------------- */
/* Warning handling                                                           */
/* -------------------------------------------------------------------------- */

async function handleWarningResult(
  form,
  submitter,
  snapshot,
  result,
) {
  let resolution = null;

  /*
   * content.js normally owns the actual warning UI.
   *
   * It may expose a resolution through onWarning.
   */
  if (
    typeof state.callbacks.onWarning ===
    "function"
  ) {
    try {
      resolution =
        await runWithTimeout(
          Promise.resolve(
            state.callbacks.onWarning(
              createWarningPayload(
                form,
                submitter,
                snapshot,
                result,
              ),
            ),
          ),
          state.config.operationTimeoutMs,
          "SUBMIT_WARNING_TIMEOUT",
        );
    } catch (error) {
      state.stats.submissionsFailed += 1;

      reportError(
        error,
        "Submission warning callback failed.",
      );

      blockSubmission(
        form,
        submitter,
        {
          reason:
            "The SanitizerPro warning decision could not be completed.",
          reasonCode:
            "WARNING_RESOLUTION_FAILED",
        },
      );

      return;
    }
  }

  const resolutionAction =
    normalizeAction(
      resolution?.action ??
      resolution,
    );

  switch (resolutionAction) {
    case ACTIONS.ALLOW:
      state.stats.submissionsAllowed += 1;

      approveAndContinue(
        form,
        submitter,
        {
          mode: "allow",
          result,
        },
      );

      return;

    case ACTIONS.MASK:
      state.stats.submissionsMasked += 1;

      await handleMaskedResult(
        form,
        submitter,
        snapshot,
        resolution?.result ??
          result,
      );

      return;

    case ACTIONS.BLOCK:
    default:
      state.stats.submissionsBlocked += 1;

      blockSubmission(
        form,
        submitter,
        {
          reason:
            "Submission blocked by SanitizerPro warning policy.",
          reasonCode:
            "WARNING_BLOCKED",
        },
      );
  }
}

/* -------------------------------------------------------------------------- */
/* Mask handling                                                              */
/* -------------------------------------------------------------------------- */

async function handleMaskedResult(
  form,
  submitter,
  snapshot,
  result,
) {
  const maskedText =
    extractMaskedText(result);

  if (
    typeof maskedText !== "string"
  ) {
    state.stats.submissionsFailed += 1;

    blockSubmission(
      form,
      submitter,
      {
        reason:
          "SanitizerPro could not produce a sanitized submission.",
        reasonCode:
          "MASK_RESULT_INVALID",
      },
    );

    return;
  }

  /*
   * We need to replace the form's outgoing values with the sanitized
   * values before continuing.
   *
   * content.js may return:
   *
   * result.maskedFields = [
   *   { index, value }
   * ]
   *
   * or:
   *
   * result.fields = [
   *   { name, value }
   * ]
   *
   * If field-level data is unavailable, we do NOT blindly replace the
   * entire form. That could corrupt application state.
   */
  const applied =
    applyMaskedFormValues(
      form,
      snapshot,
      result,
    );

  if (!applied) {
    /*
     * Fail closed. Never send the original sensitive content after
     * a masking operation could not be safely applied.
     */
    state.stats.submissionsFailed += 1;

    blockSubmission(
      form,
      submitter,
      {
        reason:
          "Sanitized values could not be safely applied to the form.",
        reasonCode:
          "MASK_APPLICATION_FAILED",
      },
    );

    return;
  }

  approveAndContinue(
    form,
    submitter,
    {
      mode: "mask",
      result,
    },
  );
}

function extractMaskedText(
  result,
) {
  if (
    result &&
    typeof result.maskedText ===
      "string"
  ) {
    return result.maskedText;
  }

  if (
    result &&
    typeof result.content ===
      "string"
  ) {
    return result.content;
  }

  return null;
}

/* -------------------------------------------------------------------------- */
/* Form masking                                                               */
/* -------------------------------------------------------------------------- */

function applyMaskedFormValues(
  form,
  snapshot,
  result,
) {
  if (
    !isValidForm(form) ||
    !snapshot
  ) {
    return false;
  }

  const fieldValues =
    extractMaskedFieldValues(
      result,
    );

  if (
    fieldValues.length === 0
  ) {
    /*
     * No field-level replacement data means we cannot safely map a
     * masked text result back onto the original form.
     */
    return false;
  }

  let changed = false;

  for (const replacement of fieldValues) {
    if (
      !replacement ||
      typeof replacement !== "object"
    ) {
      continue;
    }

    const field =
      resolveSnapshotFieldElement(
        form,
        snapshot,
        replacement,
      );

    if (!field) {
      return false;
    }

    if (
      !isWritableField(field)
    ) {
      return false;
    }

    const value =
      typeof replacement.value ===
      "string"
        ? replacement.value
        : null;

    if (value === null) {
      return false;
    }

    if (
      value.length >
      state.config.maximumFieldCharacters
    ) {
      return false;
    }

    if (
      setElementValue(
        field,
        value,
      )
    ) {
      changed = true;
    }
  }

  return changed;
}

function extractMaskedFieldValues(
  result,
) {
  if (!result || typeof result !== "object") {
    return [];
  }

  if (
    Array.isArray(
      result.maskedFields,
    )
  ) {
    return result.maskedFields;
  }

  if (
    Array.isArray(
      result.fields,
    )
  )
    return result.fields;

  return [];
}

function resolveSnapshotFieldElement(
  form,
  snapshot,
  replacement,
) {
  if (
    Number.isInteger(
      replacement.index,
    )
  ) {
    const field =
      snapshot.fields?.[
        replacement.index
      ];

    if (
      field?.element &&
      form.contains(field.element)
    ) {
      return field.element;
    }
  }

  if (
    typeof replacement.name ===
      "string" &&
    replacement.name.length > 0
  ) {
    const fields =
      getFormControls(form);

    for (const field of fields) {
      if (
        getSafeAttribute(
          field,
          "name",
        ) === replacement.name
      ) {
        return field;
      }
    }
  }

  return null;
}

/* -------------------------------------------------------------------------- */
/* Approval handling                                                          */
/* -------------------------------------------------------------------------- */

function approveAndContinue(
  form,
  submitter,
  options = {},
) {
  if (!isValidForm(form)) {
    return false;
  }

  /*
   * Register a one-time approval.
   *
   * The next submit event consumes this record immediately.
   */
  state.approvals.set(
    form,
    {
      createdAt: Date.now(),
      expiresAt:
        Date.now() +
        state.config.approvalTimeoutMs,
      mode:
        options.mode ??
        "allow",
    },
  );

  state.stats.submissionsApproved += 0;

  continueApprovedSubmission(
    form,
    submitter,
    options,
  );

  return true;
}

function consumeApproval(
  form,
) {
  const approval =
    state.approvals.get(form);

  if (!approval) {
    return null;
  }

  /*
   * Consume immediately.
   *
   * This is the important security fix that prevents permanent approval.
   */
  state.approvals.delete(form);

  if (
    approval.expiresAt <=
    Date.now()
  ) {
    return null;
  }

  return approval;
}

function clearApproval(
  form,
) {
  state.approvals.delete(form);
}

function continueApprovedSubmission(
  form,
  submitter,
  options = {},
) {
  if (
    !isValidForm(form)
  ) {
    return false;
  }

  if (
    state.continuingForms.has(form)
  ) {
    state.stats.recursiveSubmissionsPrevented += 1;
    return false;
  }

  /*
   * Mark this specific continuation.
   *
   * The next submit event consumes this marker immediately.
   */
  state.continuingForms.add(form);

  try {
    /*
     * Prefer requestSubmit(submitter) because it preserves the browser's
     * normal submitter semantics and dispatches the normal submit event.
     */
    if (
      typeof form.requestSubmit ===
      "function"
    ) {
      const validSubmitter =
        isSubmitterForForm(
          submitter,
          form,
        )
          ? submitter
          : getSubmitterForForm(
              form,
            );

      if (validSubmitter) {
        form.requestSubmit(
          validSubmitter,
        );
      } else {
        form.requestSubmit();
      }

      /*
       * The submit event should synchronously consume the continuation
       * marker. If it did not, remove it to prevent stale bypass state.
       */
      if (
        state.continuingForms.has(form)
      ) {
        state.continuingForms.delete(
          form,
        );
      }

      return true;
    }

    /*
     * Legacy fallback:
     *
     * HTMLFormElement.prototype.submit() bypasses the submit event.
     * This means no recursive monitor event will occur.
     */
    const nativeSubmit =
      getNativeFormSubmit();

    if (nativeSubmit) {
      state.continuingForms.delete(form);

      nativeSubmit.call(form);

      return true;
    }

    state.continuingForms.delete(form);

    return false;
  } catch (error) {
    state.continuingForms.delete(form);

    reportError(
      error,
      "Approved form continuation failed.",
    );

    blockSubmission(
      form,
      submitter,
      {
        reason:
          "SanitizerPro could not safely continue the approved submission.",
        reasonCode:
          "APPROVED_SUBMISSION_FAILED",
      },
    );

    return false;
  }
}

/* -------------------------------------------------------------------------- */
/* Blocking                                                                   */
/* -------------------------------------------------------------------------- */

function blockSubmission(
  form,
  submitter,
  options = {},
) {
  if (!isValidForm(form)) {
    return false;
  }

  clearApproval(form);
  state.continuingForms.delete(form);

  state.stats.submissionsBlocked += 0;

  emitEvent(
    EVENT_TYPES.ACTION_BLOCKED,
    {
      sourceType:
        SOURCE_TYPES.SUBMIT,
      reasonCode:
        options.reasonCode ??
        "SUBMISSION_BLOCKED",
    },
  );

  /*
   * Do not call form.submit().
   *
   * The entire purpose of this method is to prevent the browser/application
   * from receiving the unapproved form data.
   */
  void submitter;

  return true;
}

/* -------------------------------------------------------------------------- */
/* Form snapshot                                                              */
/* -------------------------------------------------------------------------- */

function collectFormSnapshot(
  form,
  submitter,
) {
  const fields = [];
  const textParts = [];

  let totalCharacters = 0;
  let oversized = false;
  let fieldLimitReached = false;

  const controls =
    getFormControls(form);

  for (
    let index = 0;
    index < controls.length;
    index += 1
  ) {
    if (
      fields.length >=
      state.config.maximumFields
    ) {
      fieldLimitReached = true;
      break;
    }

    const element =
      controls[index];

    if (
      !shouldInspectField(
        element,
      )
    ) {
      continue;
    }

    const field =
      createFieldSnapshot(
        element,
        index,
      );

    if (!field) {
      continue;
    }

    let value =
      field.value ?? "";

    if (
      value.length >
      state.config.maximumFieldCharacters
    ) {
      oversized = true;
      value = value.slice(
        0,
        state.config.maximumFieldCharacters,
      );
    }

    field.value =
      value;

    totalCharacters +=
      value.length;

    if (
      totalCharacters >
      state.config.maximumCombinedCharacters
    ) {
      oversized = true;
      break;
    }

    fields.push(field);

    if (value.length > 0) {
      textParts.push(value);
    }

    if (
      state.config.includeLabels &&
      field.label
    ) {
      textParts.push(
        field.label,
      );
    }

    if (
      state.config.includeButtonText &&
      field.isSubmitter &&
      field.label
    ) {
      textParts.push(
        field.label,
      );
    }
  }

  const combinedText =
    textParts.join("\n");

  if (
    combinedText.length >
    state.config.maximumCombinedCharacters
  ) {
    oversized = true;
  }

  const nonEmptyFields =
    fields.filter(
      (field) =>
        typeof field.value ===
          "string" &&
        field.value.length > 0,
    );

  return {
    type: "form-submission",
    sourceType:
      SOURCE_TYPES.SUBMIT,

    fieldCount:
      fields.length,

    fields,

    combinedText:
      combinedText.slice(
        0,
        state.config.maximumCombinedCharacters,
      ),

    empty:
      nonEmptyFields.length === 0,

    oversized,

    fieldLimitReached,

    submitter:
      createSubmitterSnapshot(
        submitter,
      ),

    createdAt:
      Date.now(),
  };
}

function createFieldSnapshot(
  element,
  index,
) {
  if (
    !element ||
    typeof element !== "object"
  ) {
    return null;
  }

  const tag =
    element.tagName?.toLowerCase();

  const type =
    getInputType(
      element,
    );

  const isContentEditable =
    element.isContentEditable === true;

  const value =
    isContentEditable
      ? getContentEditableText(
          element,
        )
      : getElementValue(
          element,
        );

  if (
    typeof value !== "string"
  ) {
    return null;
  }

  const label =
    state.config.includeLabels
      ? getFieldLabel(
          element,
        )
      : "";

  const name =
    state.config.includeNames
      ? getSafeAttribute(
          element,
          "name",
        )
      : "";

  const isSubmitter =
    isSubmitControl(
      element,
    );

  return {
    index,

    /*
     * The DOM element itself remains local.
     * This object is never sent to the service worker.
     */
    element,

    tag,
    type,

    name,

    label,

    value,

    isContentEditable,

    isSubmitter,
  };
}

function createSubmitterSnapshot(
  submitter,
) {
  if (!submitter) {
    return null;
  }

  return {
    tag:
      submitter.tagName?.toLowerCase() ??
      "",
    type:
      getInputType(
        submitter,
      ),
    name:
      getSafeAttribute(
        submitter,
        "name",
      ),
    label:
      getElementText(
        submitter,
      ).slice(
        0,
        500,
      ),
  };
}

/* -------------------------------------------------------------------------- */
/* Submission payload                                                         */
/* -------------------------------------------------------------------------- */

function createLocalSubmissionPayload(
  form,
  submitter,
  snapshot,
) {
  /*
   * This payload deliberately contains the raw form values because it
   * is passed only to the local onSubmit callback in content.js.
   *
   * It MUST NOT be forwarded to chrome.runtime.sendMessage().
   */
  return {
    type:
      "sanitizerpro-submit",
    sourceType:
      SOURCE_TYPES.SUBMIT,

    form,

    submitter,

    text:
      snapshot.combinedText,

    combinedText:
      snapshot.combinedText,

    fields:
      snapshot.fields,

    fieldCount:
      snapshot.fieldCount,

    oversized:
      snapshot.oversized,

    fieldLimitReached:
      snapshot.fieldLimitReached,

    timestamp:
      Date.now(),
  };
}

function createWarningPayload(
  form,
  submitter,
  snapshot,
  result,
) {
  return {
    type:
      "sanitizerpro-submit-warning",

    sourceType:
      SOURCE_TYPES.SUBMIT,

    form,

    submitter,

    text:
      snapshot.combinedText,

    fields:
      snapshot.fields,

    result,

    timestamp:
      Date.now(),
  };
}

/* -------------------------------------------------------------------------- */
/* DOM field handling                                                         */
/* -------------------------------------------------------------------------- */

function getFormControls(
  form,
) {
  if (
    !isValidForm(form)
  ) {
    return [];
  }

  try {
    return Array.from(
      form.elements ?? [],
    );
  } catch {
    return [];
  }
}

function shouldInspectField(
  element,
) {
  if (
    !element ||
    typeof element !== "object"
  ) {
    return false;
  }

  if (
    element.disabled === true
  ) {
    return false;
  }

  if (
    element.type === "hidden"
  ) {
    return false;
  }

  if (
    element.type === "password"
  ) {
    /*
     * Password fields are highly sensitive.
     *
     * They should not be collected by the generic submit snapshot because
     * the input monitor and credential rules handle credentials separately.
     *
     * This also avoids accidentally duplicating password values into the
     * generic form aggregation.
     */
    return false;
  }

  if (
    element.readOnly === true &&
    !element.isContentEditable
  ) {
    return false;
  }

  const tag =
    element.tagName?.toLowerCase();

  if (
    tag === "textarea" &&
    !state.config.scanTextareas
  ) {
    return false;
  }

  if (
    tag === "input" &&
    !state.config.scanTextFields
  ) {
    return false;
  }

  if (
    element.isContentEditable === true &&
    !state.config.scanContentEditable
  ) {
    return false;
  }

  if (
    isSubmitControl(
      element,
    )
  ) {
    return false;
  }

  if (
    tag === "button"
  ) {
    return false;
  }

  if (
    !state.config.includeNonTextControls &&
    !isTextLikeElement(
      element,
    )
  ) {
    return false;
  }

  return true;
}

function isTextLikeElement(
  element,
) {
  if (
    !element
  ) {
    return false;
  }

  if (
    element.isContentEditable === true
  ) {
    return true;
  }

  const tag =
    element.tagName?.toLowerCase();

  if (
    tag === "textarea"
  ) {
    return true;
  }

  if (
    tag !== "input"
  ) {
    return false;
  }

  const type =
    getInputType(
      element,
    );

  return [
    "text",
    "search",
    "email",
    "url",
    "tel",
    "number",
  ].includes(type);
}

function isWritableField(
  element,
) {
  if (
    !element ||
    element.disabled === true
  ) {
    return false;
  }

  if (
    element.readOnly === true
  ) {
    return false;
  }

  if (
    element.isContentEditable === true
  ) {
    return true;
  }

  const tag =
    element.tagName?.toLowerCase();

  return (
    tag === "input" ||
    tag === "textarea"
  );
}

function getElementValue(
  element,
) {
  if (
    !element
  ) {
    return "";
  }

  if (
    typeof element.value ===
    "string"
  ) {
    return element.value;
  }

  return "";
}

function getContentEditableText(
  element,
) {
  if (
    !element
  ) {
    return "";
  }

  /*
   * textContent avoids reading arbitrary HTML markup.
   */
  return (
    typeof element.textContent ===
    "string"
      ? element.textContent
      : ""
  );
}

function setElementValue(
  element,
  value,
) {
  if (
    !isWritableField(
      element,
    )
  ) {
    return false;
  }

  try {
    if (
      element.isContentEditable === true
    ) {
      return setContentEditableValue(
        element,
        value,
      );
    }

    const tag =
      element.tagName?.toLowerCase();

    if (
      tag === "textarea"
    ) {
      const descriptor =
        Object.getOwnPropertyDescriptor(
          HTMLTextAreaElement.prototype,
          "value",
        );

      if (
        descriptor?.set
      ) {
        descriptor.set.call(
          element,
          value,
        );
      } else {
        element.value =
          value;
      }
    } else {
      const descriptor =
        Object.getOwnPropertyDescriptor(
          HTMLInputElement.prototype,
          "value",
        );

      if (
        descriptor?.set
      ) {
        descriptor.set.call(
          element,
          value,
        );
      } else {
        element.value =
          value;
      }
    }

    dispatchValueEvents(
      element,
    );

    return true;
  } catch {
    return false;
  }
}

function setContentEditableValue(
  element,
  value,
) {
  try {
    element.textContent =
      value;

    dispatchValueEvents(
      element,
    );

    return true;
  } catch {
    return false;
  }
}

function dispatchValueEvents(
  element,
) {
  try {
    element.dispatchEvent(
      new Event(
        "input",
        {
          bubbles: true,
          composed: true,
        },
      ),
    );

    element.dispatchEvent(
      new Event(
        "change",
        {
          bubbles: true,
        },
      ),
    );
  } catch {
    // Ignore event-dispatch failures.
  }
}

/* -------------------------------------------------------------------------- */
/* Labels and metadata                                                        */
/* -------------------------------------------------------------------------- */

function getFieldLabel(
  element,
) {
  if (
    !element
  ) {
    return "";
  }

  const ariaLabel =
    getSafeAttribute(
      element,
      "aria-label",
    );

  if (ariaLabel) {
    return ariaLabel.slice(
      0,
      500,
    );
  }

  const ariaLabelledBy =
    getSafeAttribute(
      element,
      "aria-labelledby",
    );

  if (ariaLabelledBy) {
    const ids =
      ariaLabelledBy
        .split(/\s+/)
        .filter(Boolean);

    const text =
      ids
        .map((id) => {
          const label =
            document.getElementById(
              id,
            );

          return label
            ? getElementText(
                label,
              )
            : "";
        })
        .filter(Boolean)
        .join(" ");

    if (text) {
      return text.slice(
        0,
        500,
      );
    }
  }

  const id =
    getSafeAttribute(
      element,
      "id",
    );

  if (id) {
    try {
      const label =
        document.querySelector(
          `label[for="${escapeSelectorValue(id)}"]`,
        );

      if (label) {
        return getElementText(
          label,
        ).slice(
          0,
          500,
        );
      }
    } catch {
      // Ignore invalid selectors.
    }
  }

  const parentLabel =
    element.closest?.("label");

  if (parentLabel) {
    return getElementText(
      parentLabel,
    ).slice(
      0,
      500,
    );
  }

  const placeholder =
    getSafeAttribute(
      element,
      "placeholder",
    );

  if (placeholder) {
    return placeholder.slice(
      0,
      500,
    );
  }

  return "";
}

function getElementText(
  element,
) {
  if (
    !element
  ) {
    return "";
  }

  const text =
    typeof element.textContent ===
    "string"
      ? element.textContent
      : "";

  return text
    .replace(/\s+/g, " ")
    .trim();
}

function getSafeAttribute(
  element,
  attribute,
) {
  if (
    !element ||
    typeof element.getAttribute !==
      "function"
  ) {
    return "";
  }

  try {
    const value =
      element.getAttribute(
        attribute,
      );

    return typeof value ===
      "string"
      ? value.slice(
          0,
          500,
        )
      : "";
  } catch {
    return "";
  }
}

function escapeSelectorValue(
  value,
) {
  if (
    typeof CSS !== "undefined" &&
    typeof CSS.escape ===
      "function"
  ) {
    return CSS.escape(value);
  }

  return String(value).replace(
    /["\\]/g,
    "\\$&",
  );
}

/* -------------------------------------------------------------------------- */
/* Submitter detection                                                        */
/* -------------------------------------------------------------------------- */

function getSubmitterFromEvent(
  event,
  form,
) {
  if (
    event?.submitter &&
    isSubmitterForForm(
      event.submitter,
      form,
    )
  ) {
    return event.submitter;
  }

  return (
    state.activeSubmitter.get(
      form,
    ) ??
    state.trackedSubmitters?.get(
      form,
    ) ??
    null
  );
}

function getSubmitterForForm(
  form,
) {
  const tracked =
    state.activeSubmitter.get(
      form,
    );

  if (
    isSubmitterForForm(
      tracked,
      form,
    )
  ) {
    return tracked;
  }

  const stored =
    state.trackedSubmitters?.get(
      form,
    );

  if (
    isSubmitterForForm(
      stored,
      form,
    )
  ) {
    return stored;
  }

  const controls =
    getFormControls(form);

  for (const control of controls) {
    if (
      isSubmitControl(
        control,
      ) &&
      !control.disabled
    ) {
      return control;
    }
  }

  return null;
}

function isSubmitterForForm(
  element,
  form,
) {
  if (
    !element ||
    !form
  ) {
    return false;
  }

  if (
    !isSubmitControl(
      element,
    )
  ) {
    return false;
  }

  const associatedForm =
    getFormForElement(
      element,
    );

  return associatedForm === form;
}

function findSubmitterElement(
  target,
) {
  if (
    !target
  ) {
    return null;
  }

  const candidate =
    target.closest?.(
      'button[type="submit"], input[type="submit"], input[type="image"], button:not([type])',
    );

  if (
    candidate &&
    isSubmitControl(
      candidate,
    )
  ) {
    return candidate;
  }

  return null;
}

function isSubmitControl(
  element,
) {
  if (
    !element
  ) {
    return false;
  }

  const tag =
    element.tagName?.toLowerCase();

  if (
    tag === "button"
  ) {
    const type =
      getInputType(
        element,
      );

    return (
      type === "submit" ||
      type === "image" ||
      type === ""
    );
  }

  if (
    tag === "input"
  ) {
    return [
      "submit",
      "image",
    ].includes(
      getInputType(
        element,
      ),
    );
  }

  return false;
}

function getInputType(
  element,
) {
  const type =
    getSafeAttribute(
      element,
      "type",
    );

  return type
    .toLowerCase()
    .trim();
}

/* -------------------------------------------------------------------------- */
/* Form lookup                                                                */
/* -------------------------------------------------------------------------- */

function getFormFromSubmitEvent(
  event,
) {
  if (
    event?.target instanceof
    HTMLFormElement
  ) {
    return event.target;
  }

  const target =
    getEventElement(
      event,
    );

  return getFormForElement(
    target,
  );
}

function getFormForElement(
  element,
) {
  if (
    !element
  ) {
    return null;
  }

  if (
    element instanceof
    HTMLFormElement
  ) {
    return element;
  }

  if (
    element.form instanceof
    HTMLFormElement
  ) {
    return element.form;
  }

  try {
    return (
      element.closest?.(
        "form",
      ) ?? null
    );
  } catch {
    return null;
  }
}

/* -------------------------------------------------------------------------- */
/* Native form submit                                                         */
/* -------------------------------------------------------------------------- */

function getNativeFormSubmit() {
  try {
    const descriptor =
      HTMLFormElement.prototype.submit;

    return typeof descriptor ===
      "function"
      ? descriptor
      : null;
  } catch {
    return null;
  }
}

/* -------------------------------------------------------------------------- */
/* Events                                                                     */
/* -------------------------------------------------------------------------- */

function emitEvent(
  eventType,
  context = {},
) {
  state.lastEventAt =
    Date.now();

  try {
    if (
      typeof state.callbacks.onEvent ===
      "function"
    ) {
      state.callbacks.onEvent({
        eventType,
        ...sanitizeEventContext(
          context,
        ),
        timestamp:
          Date.now(),
      });
    }
  } catch (error) {
    reportError(
      error,
      "Submit monitor event callback failed.",
    );
  }
}

function reportEvent(
  eventType,
  context = {},
) {
  emitEvent(
    eventType,
    context,
  );
}

function reportError(
  error,
  message,
) {
  try {
    if (
      typeof state.callbacks.onError ===
      "function"
    ) {
      state.callbacks.onError(
        {
          error,
          message,
          sourceType:
            SOURCE_TYPES.SUBMIT,
        },
      );
    }
  } catch {
    // Never allow error reporting to break submission protection.
  }
}

/* -------------------------------------------------------------------------- */
/* Safe action normalization                                                  */
/* -------------------------------------------------------------------------- */

function normalizeAction(
  action,
) {
  if (
    typeof action !== "string"
  ) {
    return ACTIONS.BLOCK;
  }

  const normalized =
    action
      .trim()
      .toUpperCase();

  for (const value of Object.values(
    ACTIONS,
  )) {
    if (
      String(value).toUpperCase() ===
      normalized
    ) {
      return value;
    }
  }

  return ACTIONS.BLOCK;
}

/* -------------------------------------------------------------------------- */
/* Diagnostics                                                                */
/* -------------------------------------------------------------------------- */

function getSubmitMonitorStatus() {
  return {
    initialized:
      state.initialized,
    destroyed:
      state.destroyed,
    version:
      MONITOR_VERSION,
    enabled:
      state.config.enabled,
    scanSubmit:
      state.config.scanSubmit,
    dynamicForms:
      state.config.dynamicForms,
    trackedForms:
      countConnectedForms(),
    pendingForms:
      countPendingForms(),
    stats: {
      ...state.stats,
    },
    callbacks: {
      onSubmit:
        typeof state.callbacks.onSubmit ===
        "function",
      onWarning:
        typeof state.callbacks.onWarning ===
        "function",
      onError:
        typeof state.callbacks.onError ===
        "function",
      onEvent:
        typeof state.callbacks.onEvent ===
        "function",
    },
  };
}

function getSubmitMonitorDiagnostics() {
  return {
    ...getSubmitMonitorStatus(),

    configuration: {
      enabled:
        state.config.enabled,
      scanSubmit:
        state.config.scanSubmit,
      scanTextFields:
        state.config.scanTextFields,
      scanTextareas:
        state.config.scanTextareas,
      scanContentEditable:
        state.config.scanContentEditable,
      includeButtonText:
        state.config.includeButtonText,
      includeLabels:
        state.config.includeLabels,
      includeNames:
        state.config.includeNames,
      includeNonTextControls:
        state.config.includeNonTextControls,
      interceptEnterKey:
        state.config.interceptEnterKey,
      interceptClickSubmit:
        state.config.interceptClickSubmit,
      dynamicForms:
        state.config.dynamicForms,
      maximumFields:
        state.config.maximumFields,
      maximumFieldCharacters:
        state.config.maximumFieldCharacters,
      maximumCombinedCharacters:
        state.config.maximumCombinedCharacters,
    },

    forms:
      countConnectedForms(),

    observers:
      state.observers.size,

    pendingOperations:
      countPendingForms(),

    lastEventAt:
      state.lastEventAt,
  };
}

/* -------------------------------------------------------------------------- */
/* Public diagnostics helpers                                                 */
/* -------------------------------------------------------------------------- */

function getSubmitCapabilities() {
  return {
    submitEvents: true,
    dynamicForms:
      state.config.dynamicForms,
    enterKey:
      state.config.interceptEnterKey,
    submitterTracking:
      state.config.interceptClickSubmit,
    localSnapshot:
      true,
    localScanning:
      true,
    oneTimeApproval:
      true,
    failClosed:
      true,
    rawDataToServiceWorker:
      false,
  };
}

function isSubmitMonitorInitialized() {
  return (
    state.initialized &&
    !state.destroyed
  );
}

function isFormTracked(
  form,
) {
  return state.forms.has(
    form,
  );
}

/* -------------------------------------------------------------------------- */
/* Cleanup                                                                    */
/* -------------------------------------------------------------------------- */

function destroySubmitMonitor() {
  if (
    state.destroyed
  ) {
    return;
  }

  unbindEventListeners();

  for (const observer of state.observers) {
    try {
      observer.disconnect();
    } catch {
      // Ignore observer cleanup errors.
    }
  }

  state.observers.clear();

  for (const form of state.forms) {
    clearApproval(form);
    state.continuingForms.delete(
      form,
    );
    state.pendingForms.delete(
      form,
    );
  }

  state.forms.clear();

  state.initialized = false;
  state.destroyed = true;

  state.callbacks.onSubmit = null;
  state.callbacks.onWarning = null;
  state.callbacks.onError = null;
  state.callbacks.onEvent = null;
}

/* -------------------------------------------------------------------------- */
/* Utility functions                                                          */
/* -------------------------------------------------------------------------- */

function getEventElement(
  event,
) {
  const target =
    event?.target;

  if (
    target instanceof
    Element
  ) {
    return target;
  }

  return null;
}

function isTextarea(
  element,
) {
  return (
    element?.tagName?.toLowerCase() ===
    "textarea"
  );
}

function isValidForm(
  form,
) {
  return (
    typeof HTMLFormElement !==
      "undefined" &&
    form instanceof
      HTMLFormElement
  );
}

function isElementNode(
  node,
) {
  return (
    typeof Element !==
      "undefined" &&
    node instanceof Element
  );
}

function isConnectedElement(
  element,
) {
  return (
    element &&
    typeof element.isConnected ===
      "boolean"
      ? element.isConnected
      : Boolean(
          element?.parentNode,
        )
  );
}

function countConnectedForms() {
  let count = 0;

  for (const form of state.forms) {
    if (
      isConnectedElement(form)
    ) {
      count += 1;
    }
  }

  return count;
}

function countPendingForms() {
  /*
   * WeakSet cannot be enumerated.
   *
   * We therefore report whether the WeakSet is actively used through
   * pending form tracking indirectly. Exact enumeration is intentionally
   * avoided because DOM references must remain weak and local.
   */
  return null;
}

function clampInteger(
  value,
  minimum,
  maximum,
  fallback,
) {
  const number =
    Number(value);

  if (
    !Number.isFinite(number)
  ) {
    return fallback;
  }

  return Math.max(
    minimum,
    Math.min(
      maximum,
      Math.floor(number),
    ),
  );
}

function runWithTimeout(
  promise,
  timeoutMs,
  errorCode,
) {
  let timer = null;

  const timeoutPromise =
    new Promise(
      (_, reject) => {
        timer = setTimeout(
          () => {
            const error =
              new Error(
                "Operation timed out.",
              );

            error.code =
              errorCode;

            reject(error);
          },
          timeoutMs,
        );
      },
    );

  return Promise.race([
    Promise.resolve(
      promise,
    ).finally(() => {
      if (timer !== null) {
        clearTimeout(timer);
        timer = null;
      }
    }),
    timeoutPromise,
  ]);
}

function sanitizeEventContext(
  context,
) {
  const safe = {};

  if (
    context &&
    typeof context === "object"
  ) {
    if (
      typeof context.sourceType ===
      "string"
    ) {
      safe.sourceType =
        context.sourceType;
    }

    if (
      typeof context.reasonCode ===
      "string"
    ) {
      safe.reasonCode =
        context.reasonCode.slice(
          0,
          100,
        );
    }

    if (
      typeof context.action ===
      "string"
    ) {
      safe.action =
        normalizeAction(
          context.action,
        );
    }
  }

  return safe;
}

/* -------------------------------------------------------------------------- */
/* Exports                                                                    */
/* -------------------------------------------------------------------------- */

export {
  initializeSubmitMonitor,
  destroySubmitMonitor,
  getSubmitMonitorStatus,
  getSubmitMonitorDiagnostics,
  getSubmitCapabilities,
  isSubmitMonitorInitialized,
  isFormTracked,
  collectFormSnapshot,
  createLocalSubmissionPayload,
  createWarningPayload,
  getSubmitterForForm,
  isSubmitterForForm,
  normalizeConfig,
};
