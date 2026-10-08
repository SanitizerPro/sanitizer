const MAX_FILE_BYTES = 500 * 1024 * 1024;
const MAX_DISPLAY_OUTPUT_BYTES = 10 * 1024 * 1024;

const SUPPORTED_EXTENSIONS = new Set([
'.txt',
'.log',
'.conf',
'.cfg',
'.config',
'.out',
'.json',
'.yaml',
'.yml',
'.xml',
'.csv',
'.ini'
]);

const state = {
worker: null,
busy: false,
selectedFile: null,
inputMode: 'file',
inputSizeBytes: 0,
outputBlob: null,
outputText: null,
outputSizeBytes: 0,
lastStats: null,
lastProgress: 0
};

const dom = {};

document.addEventListener(
'DOMContentLoaded',
initialize
);

function initialize() {
cacheDom();
validateDom();
initializeWorker();
initializeProfiles();
initializeInputModes();
initializeFileInput();
initializeDragAndDrop();
initializeTextInput();
initializeActions();
resetUI();
}

function cacheDom() {
dom.fileModeButton =
document.getElementById(
'fileModeButton'
);

dom.textModeButton =
document.getElementById(
'textModeButton'
);

dom.fileInputPanel =
document.getElementById(
'fileInputPanel'
);

dom.textInputPanel =
document.getElementById(
'textInputPanel'
);

dom.dropZone =
document.getElementById(
'dropZone'
);

dom.fileInput =
document.getElementById(
'fileInput'
);

dom.selectedFile =
document.getElementById(
'selectedFile'
);

dom.selectedFileName =
document.getElementById(
'selectedFileName'
);

dom.selectedFileSize =
document.getElementById(
'selectedFileSize'
);

dom.removeFileButton =
document.getElementById(
'removeFileButton'
);

dom.inputText =
document.getElementById(
'inputText'
);

dom.textInputSize =
document.getElementById(
'textInputSize'
);

dom.profileSelect =
document.getElementById(
'profileSelect'
);

dom.strictMode =
document.getElementById(
'strictMode'
);

dom.statusPanel =
document.getElementById(
'statusPanel'
);

dom.statusIndicator =
document.getElementById(
'statusIndicator'
);

dom.statusText =
document.getElementById(
'statusText'
);

dom.statusMessage =
document.getElementById(
'statusMessage'
);

dom.progressContainer =
document.getElementById(
'progressContainer'
);

dom.progressLabel =
document.getElementById(
'progressLabel'
);

dom.progressPercent =
document.getElementById(
'progressPercent'
);

dom.progressBar =
document.getElementById(
'progressBar'
);

dom.progressFill =
document.getElementById(
'progressFill'
);

dom.processedSize =
document.getElementById(
'processedSize'
);

dom.progressMatchCount =
document.getElementById(
'progressMatchCount'
);

dom.errorPanel =
document.getElementById(
'errorPanel'
);

dom.errorTitle =
document.getElementById(
'errorTitle'
);

dom.errorText =
document.getElementById(
'errorText'
);

dom.sanitizeButton =
document.getElementById(
'sanitizeButton'
);

dom.cancelButton =
document.getElementById(
'cancelButton'
);

dom.clearButton =
document.getElementById(
'clearButton'
);

dom.resultSection =
document.getElementById(
'resultSection'
);

dom.outputStatus =
document.getElementById(
'outputStatus'
);

dom.statsInputSize =
document.getElementById(
'statsInputSize'
);

dom.statsOutputSize =
document.getElementById(
'statsOutputSize'
);

dom.rulesMatched =
document.getElementById(
'rulesMatched'
);

dom.totalMatches =
document.getElementById(
'totalMatches'
);

dom.matchedRulesList =
document.getElementById(
'matchedRulesList'
);

dom.outputPreviewNotice =
document.getElementById(
'outputPreviewNotice'
);

dom.outputText =
document.getElementById(
'outputText'
);

dom.largeOutputNotice =
document.getElementById(
'largeOutputNotice'
);

dom.copyButton =
document.getElementById(
'copyButton'
);

dom.downloadButton =
document.getElementById(
'downloadButton'
);
}

function validateDom() {
for (
const [name, element] of Object.entries(
dom
)
) {
if (!element) {
throw new Error(
`SanitizeLog UI initialization failed: missing element '${name}'.`
);
}
}
}

function initializeWorker() {
terminateWorker();

state.worker =
new Worker(
'./sanitizer.worker.js'
);

state.worker.onmessage =
handleWorkerMessage;

state.worker.onerror =
handleWorkerError;

state.worker.onmessageerror =
() => {
handleApplicationError(
new Error(
'The sanitizer worker returned an invalid message.'
)
);
};
}

function initializeProfiles() {
const profiles = [
{
id: 'DEFAULT_SECURITY',
name: 'Default Security Baseline'
}
];

dom.profileSelect.innerHTML = '';

for (
const profile of profiles
) {
const option =
document.createElement(
'option'
);

```
option.value =
  profile.id;

option.textContent =
  profile.name;

dom.profileSelect.appendChild(
  option
);
```

}
}

function initializeInputModes() {
dom.fileModeButton.addEventListener(
'click',
() => {
setInputMode('file');
}
);

dom.textModeButton.addEventListener(
'click',
() => {
setInputMode('text');
}
);
}

function setInputMode(mode) {
if (state.busy) {
return;
}

state.inputMode =
mode;

const fileMode =
mode === 'file';

dom.fileModeButton.classList.toggle(
'active',
fileMode
);

dom.textModeButton.classList.toggle(
'active',
!fileMode
);

dom.fileModeButton.setAttribute(
'aria-selected',
String(fileMode)
);

dom.textModeButton.setAttribute(
'aria-selected',
String(!fileMode)
);

dom.fileInputPanel.hidden =
!fileMode;

dom.textInputPanel.hidden =
fileMode;

if (!fileMode) {
dom.inputText.focus();
}
}

function initializeFileInput() {
dom.fileInput.addEventListener(
'change',
(event) => {
const file =
event.target.files &&
event.target.files[0];

```
  if (file) {
    selectFile(file);
  }
}
```

);

dom.removeFileButton.addEventListener(
'click',
removeSelectedFile
);
}

function initializeDragAndDrop() {
const zone =
dom.dropZone;

const dragEvents = [
'dragenter',
'dragover'
];

for (
const eventName of dragEvents
) {
zone.addEventListener(
eventName,
(event) => {
event.preventDefault();
event.stopPropagation();

```
    if (!state.busy) {
      zone.classList.add(
        'drag-over'
      );
    }
  }
);
```

}

const leaveEvents = [
'dragleave',
'dragend',
'drop'
];

for (
const eventName of leaveEvents
) {
zone.addEventListener(
eventName,
(event) => {
event.preventDefault();
event.stopPropagation();

```
    zone.classList.remove(
      'drag-over'
    );
  }
);
```

}

zone.addEventListener(
'drop',
(event) => {
if (state.busy) {
return;
}

```
  const file =
    event.dataTransfer &&
    event.dataTransfer.files &&
    event.dataTransfer.files[0];

  if (file) {
    selectFile(file);
  }
}
```

);
}

function initializeTextInput() {
dom.inputText.addEventListener(
'input',
() => {
const bytes =
getUtf8ByteLength(
dom.inputText.value
);

```
  dom.textInputSize.textContent =
    formatBytes(bytes);
}
```

);
}

function initializeActions() {
dom.sanitizeButton.addEventListener(
'click',
sanitize
);

dom.cancelButton.addEventListener(
'click',
cancelSanitization
);

dom.clearButton.addEventListener(
'click',
clearAll
);

dom.copyButton.addEventListener(
'click',
copyOutput
);

dom.downloadButton.addEventListener(
'click',
downloadOutput
);
}

function selectFile(file) {
if (state.busy) {
return;
}

clearError();

const validation =
validateFile(file);

if (!validation.valid) {
showError(
'Invalid file',
validation.message
);

```
return;
```

}

state.selectedFile =
file;

state.inputSizeBytes =
file.size;

dom.selectedFileName.textContent =
file.name;

dom.selectedFileSize.textContent =
`${formatBytes(file.size)} · ${getFileExtension(file.name).toUpperCase()}`;

dom.selectedFile.classList.remove(
'hidden'
);

setStatus(
'Ready',
`${file.name} is ready to sanitize.`,
'idle'
);

dom.resultSection.classList.add(
'hidden'
);
}

function removeSelectedFile() {
if (state.busy) {
return;
}

state.selectedFile =
null;

state.inputSizeBytes =
0;

dom.fileInput.value =
'';

dom.selectedFile.classList.add(
'hidden'
);

setStatus(
'Ready',
'Select a file or paste text to begin.',
'idle'
);
}

function validateFile(file) {
if (!(file instanceof File)) {
return {
valid: false,
message:
'The selected input is not a valid file.'
};
}

if (
file.size >
MAX_FILE_BYTES
) {
return {
valid: false,
message:
`The selected file is ${formatBytes(file.size)}. ` +
`The maximum supported input size is ${formatBytes(MAX_FILE_BYTES)}.`
};
}

const extension =
getFileExtension(
file.name
);

if (
!SUPPORTED_EXTENSIONS.has(
extension
)
) {
return {
valid: false,
message:
`Unsupported file format '${extension || 'unknown'}'. ` +
'Please choose a supported text-based diagnostic or configuration file.'
};
}

return {
valid: true
};
}

function getFileExtension(
filename
) {
const lastDot =
filename.lastIndexOf('.');

if (
lastDot === -1
) {
return '';
}

return filename
.slice(lastDot)
.toLowerCase();
}

function sanitize() {
if (state.busy) {
return;
}

clearError();
clearResult();

let content;
let inputSizeBytes;

if (
state.inputMode ===
'file'
) {
if (!state.selectedFile) {
showError(
'No file selected',
'Choose a supported log or configuration file before starting sanitization.'
);

```
  return;
}

const validation =
  validateFile(
    state.selectedFile
  );

if (!validation.valid) {
  showError(
    'Invalid file',
    validation.message
  );

  return;
}

content =
  state.selectedFile;

inputSizeBytes =
  state.selectedFile.size;
```

} else {
content =
dom.inputText.value;

```
inputSizeBytes =
  getUtf8ByteLength(
    content
  );

if (
  inputSizeBytes === 0
) {
  showError(
    'No text provided',
    'Paste diagnostic text before starting sanitization.'
  );

  return;
}

if (
  inputSizeBytes >
  MAX_FILE_BYTES
) {
  showError(
    'Input is too large',
    `The pasted content is ${formatBytes(inputSizeBytes)}. ` +
    `The maximum supported input size is ${formatBytes(MAX_FILE_BYTES)}.`
  );

  return;
}
```

}

state.inputSizeBytes =
inputSizeBytes;

state.outputBlob =
null;

state.outputText =
null;

state.outputSizeBytes =
0;

state.lastProgress =
0;

state.lastStats =
null;

state.busy =
true;

setProcessingUI();

const profileId =
dom.profileSelect.value ||
'DEFAULT_SECURITY';

const payload = {
content,
rules: getRulesForProfile(
profileId
),
options: {
strict:
dom.strictMode.checked
}
};

try {
state.worker.postMessage(
{
type: 'START',
payload
}
);
} catch (error) {
state.busy =
false;

```
handleApplicationError(
  error
);
```

}
}

function getRulesForProfile(
profileId
) {
if (
profileId ===
'DEFAULT_SECURITY'
) {
return [
{
id: 'common-jwt',
description:
'JSON Web Token (JWT)',
scope: 'line',
regex:
/bearer\s+(eyJ[a-zA-Z0-9_-]+.eyJ[a-zA-Z0-9_-]+.[a-zA-Z0-9_.-]+)/gi,
replacementGroup: 1,
tokenType: 'JWT'
},
{
id:
'common-password-assignment',
description:
'Generic key-value password pattern',
scope: 'line',
regex:
/(password\s*[:=]\s*)([^\s"',;]+)/gi,
replacementGroup: 2,
tokenType: 'PASSWORD'
}
];
}

throw new Error(
`Unknown security profile '${profileId}'.`
);
}

function setProcessingUI() {
dom.sanitizeButton.disabled =
true;

dom.clearButton.disabled =
true;

dom.cancelButton.classList.remove(
'hidden'
);

dom.cancelButton.disabled =
false;

dom.progressContainer.classList.remove(
'hidden'
);

dom.progressLabel.textContent =
'Sanitizing...';

updateProgress(
0,
0,
state.inputSizeBytes
);

setStatus(
'Sanitizing',
'Processing your file locally in your browser.',
'processing'
);

dom.resultSection.classList.add(
'hidden'
);
}

function handleWorkerMessage(
event
) {
const message =
event.data;

if (
!message ||
typeof message.type !==
'string'
) {
handleApplicationError(
new Error(
'The sanitizer worker returned an invalid response.'
)
);

```
return;
```

}

switch (
message.type
) {
case 'PROGRESS':
handleProgress(
message.payload
);
break;

```
case 'COMPLETE':
  handleCompleteText(
    message.payload
  );
  break;

case 'COMPLETE_BLOB':
  handleCompleteBlob(
    message.payload
  );
  break;

case 'ERROR':
  handleWorkerErrorMessage(
    message.error
  );
  break;

case 'CANCELLED':
  handleCancelled();
  break;

default:
  handleApplicationError(
    new Error(
      `Unexpected worker message type '${message.type}'.`
    )
  );
```

}
}

function handleProgress(
payload
) {
if (!payload) {
return;
}

const totalBytes =
Number(
payload.totalBytes
);

const processedBytes =
Number(
payload.processedBytes
);

let percent =
Number(
payload.percent
);

if (
!Number.isFinite(
percent
)
) {
percent =
totalBytes > 0
? (
processedBytes /
totalBytes
) *
100
: 100;
}

percent =
Math.max(
0,
Math.min(
100,
Math.floor(percent)
)
);

if (
percent <
state.lastProgress
) {
percent =
state.lastProgress;
}

state.lastProgress =
percent;

updateProgress(
percent,
processedBytes,
totalBytes
);
}

function updateProgress(
percent,
processedBytes,
totalBytes
) {
const safePercent =
Math.max(
0,
Math.min(
100,
Math.floor(
Number(percent) || 0
)
)
);

dom.progressPercent.textContent =
`${safePercent}%`;

dom.progressFill.style.width =
`${safePercent}%`;

dom.progressBar.setAttribute(
'aria-valuenow',
String(safePercent)
);

dom.processedSize.textContent =
`${formatBytes(processedBytes)} / ${formatBytes(totalBytes)} processed`;

const currentMatches =
getTotalMatches(
state.lastStats
);

dom.progressMatchCount.textContent =
`${currentMatches} ${currentMatches === 1 ? 'match' : 'matches'}`;
}

function handleCompleteText(
payload
) {
if (!payload) {
handleApplicationError(
new Error(
'The sanitizer completed without a result payload.'
)
);

```
return;
```

}

const sanitizedText =
typeof payload.sanitizedText ===
'string'
? payload.sanitizedText
: '';

const outputBlob =
new Blob(
[sanitizedText],
{
type:
'text/plain;charset=utf-8'
}
);

finalizeResult(
outputBlob,
sanitizedText,
payload.stats
);
}

async function handleCompleteBlob(
payload
) {
if (
!payload ||
!(payload.blob instanceof Blob)
) {
handleApplicationError(
new Error(
'The sanitizer completed without a valid output Blob.'
)
);

```
return;
```

}

const blob =
payload.blob;

let previewText =
null;

if (
blob.size <=
MAX_DISPLAY_OUTPUT_BYTES
) {
try {
previewText =
await blob.text();
} catch {
previewText =
null;
}
}

finalizeResult(
blob,
previewText,
payload.stats
);
}

function finalizeResult(
blob,
previewText,
stats
) {
state.busy =
false;

state.outputBlob =
blob;

state.outputText =
previewText;

state.outputSizeBytes =
blob.size;

state.lastStats =
stats || {
matches: {}
};

updateProgress(
100,
state.inputSizeBytes,
state.inputSizeBytes
);

dom.progressLabel.textContent =
'Sanitization complete';

setStatus(
'Complete',
'Your sanitized result is ready.',
'success'
);

dom.cancelButton.classList.add(
'hidden'
);

dom.clearButton.disabled =
false;

dom.sanitizeButton.disabled =
false;

renderResult(
stats
);
}

function renderResult(
stats
) {
dom.resultSection.classList.remove(
'hidden'
);

dom.statsInputSize.textContent =
formatBytes(
state.inputSizeBytes
);

dom.statsOutputSize.textContent =
formatBytes(
state.outputSizeBytes
);

const matches =
normalizeMatches(
stats
);

const totalMatches =
Object.values(
matches
).reduce(
(
total,
value
) =>
total +
Number(value || 0),
0
);

const matchedRules =
Object.keys(
matches
).filter(
(ruleId) =>
Number(
matches[ruleId]
) > 0
);

dom.rulesMatched.textContent =
String(
matchedRules.length
);

dom.totalMatches.textContent =
String(
totalMatches
);

renderMatchedRules(
matchedRules,
matches
);

if (
state.outputText !==
null
) {
dom.outputText.value =
state.outputText;

```
dom.outputText.classList.remove(
  'hidden'
);

dom.largeOutputNotice.classList.add(
  'hidden'
);

dom.copyButton.disabled =
  false;

dom.outputPreviewNotice.textContent =
  `${formatBytes(state.outputSizeBytes)} preview loaded.`;
```

} else {
dom.outputText.value =
'';

```
dom.outputText.classList.remove(
  'hidden'
);

dom.largeOutputNotice.classList.remove(
  'hidden'
);

dom.copyButton.disabled =
  true;

dom.outputPreviewNotice.textContent =
  'Large result kept as a downloadable Blob.';
```

}

dom.downloadButton.disabled =
false;

dom.outputStatus.textContent =
totalMatches === 0
? 'No configured sensitive values were detected.'
: `${totalMatches} sensitive value${totalMatches === 1 ? '' : 's'} replaced.`;

requestAnimationFrame(
() => {
dom.resultSection.scrollIntoView(
{
behavior:
'smooth',
block:
'start'
}
);
}
);
}

function renderMatchedRules(
ruleIds,
matches
) {
dom.matchedRulesList.innerHTML =
'';

if (
ruleIds.length ===
0
) {
const item =
document.createElement(
'li'
);

```
item.textContent =
  'No configured rules matched';

dom.matchedRulesList.appendChild(
  item
);

return;
```

}

for (
const ruleId of ruleIds
) {
const item =
document.createElement(
'li'
);

```
item.textContent =
  `${getRuleDisplayName(ruleId)} · ${matches[ruleId]}`;

dom.matchedRulesList.appendChild(
  item
);
```

}
}

function getRuleDisplayName(
ruleId
) {
const names = {
'common-jwt':
'JWT',
'common-password-assignment':
'Password assignment'
};

return (
names[ruleId] ||
ruleId
);
}

function normalizeMatches(
stats
) {
if (
!stats ||
!stats.matches ||
typeof stats.matches !==
'object'
) {
return {};
}

return stats.matches;
}

function getTotalMatches(
stats
) {
const matches =
normalizeMatches(
stats
);

return Object.values(
matches
).reduce(
(
total,
value
) =>
total +
Number(value || 0),
0
);
}

function cancelSanitization() {
if (
!state.busy ||
!state.worker
) {
return;
}

dom.cancelButton.disabled =
true;

setStatus(
'Cancelling',
'Stopping the sanitization operation...',
'processing'
);

try {
state.worker.postMessage({
type: 'CANCEL'
});
} catch (error) {
handleApplicationError(
error
);
}
}

function handleCancelled() {
state.busy =
false;

state.outputBlob =
null;

state.outputText =
null;

state.outputSizeBytes =
0;

dom.cancelButton.classList.add(
'hidden'
);

dom.cancelButton.disabled =
false;

dom.clearButton.disabled =
false;

dom.sanitizeButton.disabled =
false;

dom.progressContainer.classList.add(
'hidden'
);

setStatus(
'Cancelled',
'No sanitized output was produced.',
'cancelled'
);
}

function handleWorkerErrorMessage(
message
) {
state.busy =
false;

dom.cancelButton.classList.add(
'hidden'
);

dom.cancelButton.disabled =
false;

dom.clearButton.disabled =
false;

dom.sanitizeButton.disabled =
false;

dom.progressContainer.classList.add(
'hidden'
);

showError(
'Sanitization failed',
message ||
'The sanitizer worker reported an unknown error.'
);

setStatus(
'Failed',
'The original input was not modified.',
'error'
);
}

function handleWorkerError(
event
) {
const message =
event &&
event.message
? event.message
: 'The sanitizer worker stopped unexpectedly.';

handleApplicationError(
new Error(message)
);
}

function handleApplicationError(
error
) {
state.busy =
false;

dom.cancelButton.classList.add(
'hidden'
);

dom.cancelButton.disabled =
false;

dom.clearButton.disabled =
false;

dom.sanitizeButton.disabled =
false;

dom.progressContainer.classList.add(
'hidden'
);

showError(
'Sanitization failed',
error instanceof Error
? error.message
: String(error)
);

setStatus(
'Failed',
'The original input was not modified.',
'error'
);

terminateWorker();
initializeWorker();
}

async function copyOutput() {
if (
typeof state.outputText !==
'string'
) {
return;
}

try {
if (
navigator.clipboard &&
typeof navigator.clipboard.writeText ===
'function'
) {
await navigator.clipboard.writeText(
state.outputText
);
} else {
dom.outputText.focus();
dom.outputText.select();
document.execCommand(
'copy'
);
dom.outputText.setSelectionRange(
0,
0
);
}

```
const original =
  dom.copyButton.textContent;

dom.copyButton.textContent =
  'Copied';

window.setTimeout(
  () => {
    dom.copyButton.textContent =
      original;
  },
  1500
);
```

} catch (error) {
showError(
'Copy failed',
'The browser did not allow the sanitized output to be copied automatically.'
);
}
}

function downloadOutput() {
if (
!(state.outputBlob instanceof Blob)
) {
return;
}

const filename =
buildOutputFilename();

const url =
URL.createObjectURL(
state.outputBlob
);

const anchor =
document.createElement(
'a'
);

anchor.href =
url;

anchor.download =
filename;

anchor.style.display =
'none';

document.body.appendChild(
anchor
);

anchor.click();
anchor.remove();

window.setTimeout(
() => {
URL.revokeObjectURL(
url
);
},
1000
);
}

function buildOutputFilename() {
if (
state.selectedFile
) {
const original =
state.selectedFile.name;

```
const dot =
  original.lastIndexOf('.');

if (
  dot > 0
) {
  return (
    original.slice(
      0,
      dot
    ) +
    '-sanitized' +
    original.slice(dot)
  );
}

return (
  original +
  '-sanitized'
);
```

}

return 'sanitized-output.txt';
}

function clearAll() {
if (state.busy) {
cancelSanitization();
return;
}

state.selectedFile =
null;

state.inputSizeBytes =
0;

state.outputBlob =
null;

state.outputText =
null;

state.outputSizeBytes =
0;

state.lastStats =
null;

state.lastProgress =
0;

dom.fileInput.value =
'';

dom.inputText.value =
'';

dom.textInputSize.textContent =
'0 B';

dom.selectedFile.classList.add(
'hidden'
);

clearError();
clearResult();

dom.progressContainer.classList.add(
'hidden'
);

dom.progressFill.style.width =
'0%';

dom.progressPercent.textContent =
'0%';

dom.progressBar.setAttribute(
'aria-valuenow',
'0'
);

setStatus(
'Ready',
'Select a file or paste text to begin.',
'idle'
);

setInputMode(
'file'
);
}

function clearResult() {
dom.resultSection.classList.add(
'hidden'
);

dom.outputText.value =
'';

dom.largeOutputNotice.classList.add(
'hidden'
);

dom.copyButton.disabled =
true;

dom.downloadButton.disabled =
true;

dom.matchedRulesList.innerHTML =
'';

dom.statsInputSize.textContent =
'0 B';

dom.statsOutputSize.textContent =
'0 B';

dom.rulesMatched.textContent =
'0';

dom.totalMatches.textContent =
'0';
}

function clearError() {
dom.errorPanel.classList.add(
'hidden'
);

dom.errorText.textContent =
'';
}

function showError(
title,
message
) {
dom.errorTitle.textContent =
title;

dom.errorText.textContent =
message;

dom.errorPanel.classList.remove(
'hidden'
);
}

function setStatus(
title,
message,
type
) {
dom.statusText.textContent =
title;

dom.statusMessage.textContent =
message;

dom.statusPanel.classList.remove(
'status-idle',
'status-processing',
'status-success',
'status-error',
'status-cancelled'
);

dom.statusPanel.classList.add(
`status-${type}`
);
}

function resetUI() {
state.busy =
false;

dom.sanitizeButton.disabled =
false;

dom.cancelButton.classList.add(
'hidden'
);

dom.clearButton.disabled =
false;

dom.progressContainer.classList.add(
'hidden'
);

dom.resultSection.classList.add(
'hidden'
);

dom.errorPanel.classList.add(
'hidden'
);

setStatus(
'Ready',
'Select a file or paste text to begin.',
'idle'
);
}

function terminateWorker() {
if (
state.worker
) {
try {
state.worker.terminate();
} catch {
// Worker termination is best-effort.
}

```
state.worker =
  null;
```

}
}

function getUtf8ByteLength(
value
) {
if (
typeof TextEncoder !==
'undefined'
) {
return new TextEncoder()
.encode(value)
.byteLength;
}

return unescape(
encodeURIComponent(
value
)
).length;
}

function formatBytes(
bytes
) {
const value =
Number(bytes);

if (
!Number.isFinite(
value
) ||
value <= 0
) {
return '0 B';
}

const units = [
'B',
'KB',
'MB',
'GB'
];

const exponent =
Math.min(
Math.floor(
Math.log(value) /
Math.log(1024)
),
units.length - 1
);

const amount =
value /
Math.pow(
1024,
exponent
);

const decimals =
exponent === 0
? 0
: amount >= 100
? 0
: amount >= 10
? 1
: 2;

return (
amount.toFixed(
decimals
) +
' ' +
units[exponent]
);
}
