'use strict';

const COMMON_RULES = [
{
id: 'common-jwt',
description: 'JSON Web Token (JWT)',
scope: 'line',
regex: /bearer\s+(eyJ[a-zA-Z0-9_-]+.eyJ[a-zA-Z0-9_-]+.[a-zA-Z0-9_.-]+)/gi,
replacementGroup: 1,
tokenType: 'JWT'
},
{
id: 'common-password-assignment',
description: 'Generic key-value password pattern',
scope: 'line',
regex: /(password\s*[:=]\s*)([^\s"',;]+)/gi,
replacementGroup: 2,
tokenType: 'PASSWORD'
}
];

const PROFILES = {
DEFAULT_SECURITY: {
id: 'DEFAULT_SECURITY',
name: 'Default Security Baseline',
description: 'Standard security detection profile',
rules: COMMON_RULES
}
};

const elements = {
inputText: document.getElementById('inputText'),
fileInput: document.getElementById('fileInput'),
clearButton: document.getElementById('clearButton'),

profileSelect: document.getElementById('profileSelect'),
strictMode: document.getElementById('strictMode'),
sanitizeButton: document.getElementById('sanitizeButton'),

statusPanel: document.getElementById('statusPanel'),
statusText: document.getElementById('statusText'),
progressPercent: document.getElementById('progressPercent'),
progressBar: document.getElementById('progressBar'),

outputText: document.getElementById('outputText'),
copyButton: document.getElementById('copyButton'),
downloadButton: document.getElementById('downloadButton'),

errorPanel: document.getElementById('errorPanel'),
errorText: document.getElementById('errorText'),

inputSize: document.getElementById('inputSize'),
outputSize: document.getElementById('outputSize'),
outputStatus: document.getElementById('outputStatus'),

rulesMatched: document.getElementById('rulesMatched'),
totalMatches: document.getElementById('totalMatches'),
statsInputSize: document.getElementById('statsInputSize'),
statsOutputSize: document.getElementById('statsOutputSize'),

matchedRules: document.getElementById('matchedRules'),
matchedRulesList: document.getElementById('matchedRulesList')
};

let worker = null;
let currentRunId = 0;
let currentInputFileName = null;
let isProcessing = false;

initialize();

function initialize() {
validateRequiredElements();
populateProfiles();
attachEventListeners();
updateInputSize();
updateOutputState();
setStatus('Ready', 0);
}

function validateRequiredElements() {
const required = [
'inputText',
'fileInput',
'clearButton',
'profileSelect',
'strictMode',
'sanitizeButton',
'statusText',
'progressPercent',
'progressBar',
'outputText',
'copyButton',
'downloadButton',
'errorPanel',
'errorText',
'inputSize',
'outputSize',
'outputStatus',
'rulesMatched',
'totalMatches',
'statsInputSize',
'statsOutputSize',
'matchedRules',
'matchedRulesList'
];

for (const key of required) {
if (!elements[key]) {
throw new Error(`SanitizeLog UI initialization failed: missing element '${key}'.`);
}
}
}

function populateProfiles() {
elements.profileSelect.innerHTML = '';

for (const profile of Object.values(PROFILES)) {
const option = document.createElement('option');
option.value = profile.id;
option.textContent = profile.name;
elements.profileSelect.appendChild(option);
}

elements.profileSelect.value = 'DEFAULT_SECURITY';
}

function attachEventListeners() {
elements.inputText.addEventListener('input', () => {
currentInputFileName = null;
updateInputSize();
hideError();
});

elements.fileInput.addEventListener('change', handleFileSelection);

elements.clearButton.addEventListener('click', clearAll);

elements.sanitizeButton.addEventListener('click', startSanitization);

elements.copyButton.addEventListener('click', copyOutput);

elements.downloadButton.addEventListener('click', downloadOutput);

window.addEventListener('beforeunload', terminateWorker);
}

async function handleFileSelection(event) {
const file = event.target.files?.[0];

if (!file) {
return;
}

try {
hideError();

```
setStatus('Loading file...', 0);

const text = await file.text();

elements.inputText.value = text;
currentInputFileName = file.name;

updateInputSize();
updateOutputState();

setStatus('File loaded', 0);
```

} catch (error) {
showError(
error instanceof Error
? error.message
: String(error)
);

```
setStatus('Ready', 0);
```

} finally {
elements.fileInput.value = '';
}
}

async function startSanitization() {
if (isProcessing) {
return;
}

const input = elements.inputText.value;

if (!input) {
resetOutput();

```
setStatus('Nothing to sanitize', 0);

elements.inputText.focus();

return;
```

}

const profileId = elements.profileSelect.value;
const profile = PROFILES[profileId];

if (!profile) {
showError(`Unknown security profile '${profileId}'.`);
return;
}

if (!Array.isArray(profile.rules) || profile.rules.length === 0) {
showError(`Security profile '${profileId}' contains no rules.`);
return;
}

const runId = ++currentRunId;

isProcessing = true;

hideError();
resetOutput();

elements.sanitizeButton.disabled = true;
elements.clearButton.disabled = true;
elements.fileInput.disabled = true;
elements.profileSelect.disabled = true;
elements.strictMode.disabled = true;

setStatus('Sanitizing...', 0);

try {
worker = createWorker();

```
const result = await runWorker(
  worker,
  input,
  profile.rules,
  {
    strict: elements.strictMode.checked
  },
  runId
);

if (runId !== currentRunId) {
  return;
}

finishSanitization(result.output, result.stats, input);
```

} catch (error) {
if (runId !== currentRunId) {
return;
}

```
const message =
  error instanceof Error
    ? error.message
    : String(error);

showError(message);

setStatus('Sanitization failed', 0);

resetOutput();
```

} finally {
if (runId === currentRunId) {
isProcessing = false;

```
  elements.sanitizeButton.disabled = false;
  elements.clearButton.disabled = false;
  elements.fileInput.disabled = false;
  elements.profileSelect.disabled = false;
  elements.strictMode.disabled = false;

  terminateWorker();
}
```

}
}

function createWorker() {
const workerInstance = new Worker(
'./sanitizer.worker.js',
{
type: 'classic'
}
);

return workerInstance;
}

function runWorker(workerInstance, content, rules, options, runId) {
return new Promise((resolve, reject) => {
let settled = false;

```
const cleanup = () => {
  workerInstance.onmessage = null;
  workerInstance.onerror = null;
  workerInstance.onmessageerror = null;
};

const fail = (error) => {
  if (settled) {
    return;
  }

  settled = true;
  cleanup();
  reject(
    error instanceof Error
      ? error
      : new Error(String(error))
  );
};

const succeed = (result) => {
  if (settled) {
    return;
  }

  settled = true;
  cleanup();
  resolve(result);
};

workerInstance.onmessage = async (event) => {
  if (runId !== currentRunId) {
    return;
  }

  const message = event.data;

  if (!message || typeof message.type !== 'string') {
    fail(new Error('Worker returned an invalid message.'));
    return;
  }

  switch (message.type) {
    case 'PROGRESS': {
      handleProgress(message.payload);
      break;
    }

    case 'COMPLETE': {
      if (!message.payload) {
        fail(new Error('Worker returned an invalid COMPLETE payload.'));
        return;
      }

      succeed({
        output: String(message.payload.sanitizedText ?? ''),
        stats: normalizeStats(message.payload.stats)
      });

      break;
    }

    case 'COMPLETE_BLOB': {
      if (!message.payload?.blob) {
        fail(new Error('Worker returned an invalid COMPLETE_BLOB payload.'));
        return;
      }

      try {
        const output = await message.payload.blob.text();

        succeed({
          output,
          stats: normalizeStats(message.payload.stats)
        });
      } catch (error) {
        fail(
          error instanceof Error
            ? error
            : new Error(String(error))
        );
      }

      break;
    }

    case 'ERROR': {
      fail(
        new Error(
          typeof message.error === 'string'
            ? message.error
            : 'Sanitizer worker failed.'
        )
      );

      break;
    }

    case 'CANCELLED': {
      fail(new Error('Sanitization was cancelled.'));
      break;
    }

    default: {
      fail(
        new Error(
          `Unexpected worker message type '${message.type}'.`
        )
      );
    }
  }
};

workerInstance.onerror = (event) => {
  fail(
    new Error(
      event?.message ||
      'Sanitizer worker encountered an execution error.'
    )
  );
};

workerInstance.onmessageerror = () => {
  fail(
    new Error(
      'Sanitizer worker message could not be deserialized.'
    )
  );
};

try {
  workerInstance.postMessage({
    type: 'START',
    payload: {
      content,
      rules,
      options
    }
  });
} catch (error) {
  fail(
    error instanceof Error
      ? error
      : new Error(String(error))
  );
}
```

});
}

function handleProgress(payload) {
if (!payload || typeof payload !== 'object') {
return;
}

const processedBytes = Number(payload.processedBytes);
const totalBytes = Number(payload.totalBytes);
const percent = Number(payload.percent);

if (
!Number.isFinite(processedBytes) ||
!Number.isFinite(totalBytes) ||
!Number.isFinite(percent)
) {
return;
}

const safePercent = Math.max(
0,
Math.min(
100,
Math.floor(percent)
)
);

elements.progressPercent.textContent = `${safePercent}%`;

elements.progressBar.style.width = `${safePercent}%`;
elements.progressBar.setAttribute(
'aria-valuenow',
String(safePercent)
);

if (totalBytes > 0) {
elements.statusText.textContent =
`Sanitizing... ${formatBytes(processedBytes)} / ${formatBytes(totalBytes)}`;
} else {
elements.statusText.textContent = 'Sanitizing...';
}
}

function finishSanitization(output, stats, input) {
const sanitizedOutput = String(output ?? '');
const inputSize = utf8ByteLength(input);
const outputSize = utf8ByteLength(sanitizedOutput);

elements.outputText.value = sanitizedOutput;

elements.inputSize.textContent = formatBytes(inputSize);
elements.outputSize.textContent = formatBytes(outputSize);

elements.statsInputSize.textContent = formatBytes(inputSize);
elements.statsOutputSize.textContent = formatBytes(outputSize);

const matchCounts = stats?.matches || {};
const totalMatches = Object.values(matchCounts)
.reduce(
(total, value) => total + normalizeCount(value),
0
);

const matchedRuleIds = Object.entries(matchCounts)
.filter(([, count]) => normalizeCount(count) > 0)
.map(([ruleId]) => ruleId);

elements.rulesMatched.textContent =
String(matchedRuleIds.length);

elements.totalMatches.textContent =
String(totalMatches);

renderMatchedRules(matchCounts);

elements.outputStatus.textContent =
sanitizedOutput.length > 0
? 'Sanitization completed successfully'
: 'Sanitization completed with empty output';

elements.copyButton.disabled = false;
elements.downloadButton.disabled = false;

setStatus('Sanitization complete', 100);
}

function renderMatchedRules(matchCounts) {
elements.matchedRulesList.replaceChildren();

const entries = Object.entries(matchCounts)
.filter(([, count]) => normalizeCount(count) > 0);

if (entries.length === 0) {
elements.matchedRules.hidden = true;
return;
}

for (const [ruleId, count] of entries) {
const rule = findRuleById(ruleId);

```
const item = document.createElement('li');

const name = document.createElement('span');
name.className = 'matched-rule-name';
name.textContent =
  rule?.description ||
  ruleId;

const quantity = document.createElement('span');
quantity.className = 'matched-rule-count';
quantity.textContent =
  String(normalizeCount(count));

item.appendChild(name);
item.appendChild(quantity);

elements.matchedRulesList.appendChild(item);
```

}

elements.matchedRules.hidden = false;
}

function findRuleById(ruleId) {
for (const profile of Object.values(PROFILES)) {
const rule = profile.rules.find(
(candidate) => candidate.id === ruleId
);

```
if (rule) {
  return rule;
}
```

}

return null;
}

async function copyOutput() {
const output = elements.outputText.value;

if (!output) {
return;
}

try {
await navigator.clipboard.writeText(output);

```
const originalText = elements.copyButton.textContent;

elements.copyButton.textContent = 'Copied';

window.setTimeout(() => {
  elements.copyButton.textContent = originalText;
}, 1500);
```

} catch (error) {
try {
elements.outputText.focus();
elements.outputText.select();

```
  const copied = document.execCommand('copy');

  if (!copied) {
    throw new Error('Clipboard copy was rejected.');
  }

  const originalText = elements.copyButton.textContent;

  elements.copyButton.textContent = 'Copied';

  window.setTimeout(() => {
    elements.copyButton.textContent = originalText;
  }, 1500);

} catch (fallbackError) {
  showError(
    fallbackError instanceof Error
      ? fallbackError.message
      : String(fallbackError)
  );
}
```

}
}

function downloadOutput() {
const output = elements.outputText.value;

if (!output) {
return;
}

const filename = createOutputFilename(
currentInputFileName
);

const blob = new Blob(
[output],
{
type: 'text/plain;charset=utf-8'
}
);

const url = URL.createObjectURL(blob);

const link = document.createElement('a');

link.href = url;
link.download = filename;
link.rel = 'noopener';

document.body.appendChild(link);
link.click();
link.remove();

URL.revokeObjectURL(url);
}

function createOutputFilename(originalName) {
if (!originalName) {
return 'sanitized-output.txt';
}

const lastDot = originalName.lastIndexOf('.');

if (lastDot <= 0) {
return `${originalName}-sanitized.txt`;
}

const base = originalName.slice(0, lastDot);
const extension = originalName.slice(lastDot);

return `${base}-sanitized${extension}`;
}

function clearAll() {
currentRunId++;

terminateWorker();

isProcessing = false;
currentInputFileName = null;

elements.inputText.value = '';
elements.fileInput.value = '';

resetOutput();
hideError();

elements.sanitizeButton.disabled = false;
elements.clearButton.disabled = false;
elements.fileInput.disabled = false;
elements.profileSelect.disabled = false;
elements.strictMode.disabled = false;

updateInputSize();

setStatus('Ready', 0);

elements.inputText.focus();
}

function resetOutput() {
elements.outputText.value = '';

elements.outputSize.textContent = '0 B';
elements.outputStatus.textContent = 'No output generated';

elements.statsInputSize.textContent =
formatBytes(
utf8ByteLength(elements.inputText.value)
);

elements.statsOutputSize.textContent = '0 B';

elements.rulesMatched.textContent = '0';
elements.totalMatches.textContent = '0';

elements.matchedRulesList.replaceChildren();
elements.matchedRules.hidden = true;

elements.copyButton.disabled = true;
elements.downloadButton.disabled = true;
}

function updateOutputState() {
const hasOutput =
elements.outputText.value.length > 0;

elements.copyButton.disabled = !hasOutput;
elements.downloadButton.disabled = !hasOutput;
}

function updateInputSize() {
const size = utf8ByteLength(
elements.inputText.value
);

elements.inputSize.textContent =
formatBytes(size);

elements.statsInputSize.textContent =
formatBytes(size);
}

function setStatus(status, percent) {
const safePercent = Math.max(
0,
Math.min(
100,
Number.isFinite(Number(percent))
? Math.floor(Number(percent))
: 0
)
);

elements.statusText.textContent = status;
elements.progressPercent.textContent = `${safePercent}%`;

elements.progressBar.style.width =
`${safePercent}%`;

elements.progressBar.setAttribute(
'aria-valuenow',
String(safePercent)
);
}

function showError(message) {
elements.errorText.textContent =
String(message || 'An unknown error occurred.');

elements.errorPanel.hidden = false;
}

function hideError() {
elements.errorPanel.hidden = true;
elements.errorText.textContent = '';
}

function normalizeStats(stats) {
if (!stats || typeof stats !== 'object') {
return {
matches: {}
};
}

return {
matches:
stats.matches &&
typeof stats.matches === 'object'
? stats.matches
: {}
};
}

function normalizeCount(value) {
const number = Number(value);

if (!Number.isFinite(number) || number < 0) {
return 0;
}

return Math.floor(number);
}

function utf8ByteLength(value) {
return new TextEncoder()
.encode(String(value ?? ''))
.byteLength;
}

function formatBytes(bytes) {
const value = Number(bytes);

if (!Number.isFinite(value) || value <= 0) {
return '0 B';
}

const units = [
'B',
'KB',
'MB',
'GB'
];

let size = value;
let unitIndex = 0;

while (
size >= 1024 &&
unitIndex < units.length - 1
) {
size /= 1024;
unitIndex++;
}

if (unitIndex === 0) {
return `${Math.round(size)} B`;
}

return `${size.toFixed(size >= 10 ? 0 : 1)} ${units[unitIndex]}`;
}

function terminateWorker() {
if (!worker) {
return;
}

try {
worker.terminate();
} catch {
// Worker termination is best-effort.
}

worker = null;
}
