const MAX_FILE_BYTES = 500 * 1024 * 1024;
const MAX_FILE_MB = 500;

/*

* Loading a very large sanitized output into a textarea would
* unnecessarily create another large JavaScript string.
*
* Outputs up to this size are displayed in the textarea.
* Larger outputs remain as a Blob and can be downloaded directly.
  */
  const MAX_DISPLAY_OUTPUT_BYTES = 10 * 1024 * 1024;

const SUPPORTED_FILE_EXTENSIONS = [
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
];

const inputElement =
document.getElementById('inputText');

const outputElement =
document.getElementById('outputText');

const fileInput =
document.getElementById('fileInput');

const clearButton =
document.getElementById('clearButton');

const sanitizeButton =
document.getElementById('sanitizeButton');

const copyButton =
document.getElementById('copyButton');

const downloadButton =
document.getElementById('downloadButton');

const strictMode =
document.getElementById('strictMode');

const profileSelect =
document.getElementById('profileSelect');

const statusPanel =
document.getElementById('statusPanel');

const statusText =
document.getElementById('statusText');

const progressPercent =
document.getElementById('progressPercent');

const progressBar =
document.getElementById('progressBar');

const errorPanel =
document.getElementById('errorPanel');

const errorText =
document.getElementById('errorText');

const inputSize =
document.getElementById('inputSize');

const outputSize =
document.getElementById('outputSize');

const outputStatus =
document.getElementById('outputStatus');

const rulesMatched =
document.getElementById('rulesMatched');

const totalMatches =
document.getElementById('totalMatches');

const statsInputSize =
document.getElementById('statsInputSize');

const statsOutputSize =
document.getElementById('statsOutputSize');

const matchedRules =
document.getElementById('matchedRules');

const matchedRulesList =
document.getElementById('matchedRulesList');

let worker = null;

let selectedFile = null;

let selectedFileName =
'sanitized-output.txt';

let lastOutputText = '';

let lastOutputBlob = null;

let lastInputBytes = 0;

let lastOutputBytes = 0;

const COMMON_RULES = [
{
id: 'common-jwt',
description: 'JSON Web Token (JWT)',
scope: 'line',
regex:
/bearer\s+(eyJ[a-zA-Z0-9_-]+.[a-zA-Z0-9_-]+.[a-zA-Z0-9_.-]+)/gi,
replacementGroup: 1,
tokenType: 'JWT'
},

{
id: 'common-password-assignment',
description:
'Generic key-value password pattern',
scope: 'line',
regex:
/(password\s*[:=]\s*)([^\s"',;]+)/gi,
replacementGroup: 2,
tokenType: 'PASSWORD'
}
];

const PROFILES = {
DEFAULT_SECURITY: {
id: 'DEFAULT_SECURITY',
name: 'Default Security Baseline',
description:
'Standard security detection profile',
rules: COMMON_RULES
}
};

/* =========================================================
INITIALIZATION
========================================================= */

initialize();

function initialize() {
validateDom();

populateProfiles();

updateInputSize();

updateOutputState();

updateStatistics({
matches: {}
});

setProgress(0);

setStatus(
'Ready',
'Add diagnostic content or load a local file.'
);

inputElement.addEventListener(
'input',
handleInputChange
);

fileInput.addEventListener(
'change',
handleFileSelection
);

clearButton.addEventListener(
'click',
clearInput
);

sanitizeButton.addEventListener(
'click',
sanitize
);

copyButton.addEventListener(
'click',
copyOutput
);

downloadButton.addEventListener(
'click',
downloadOutput
);

window.addEventListener(
'beforeunload',
() => {
terminateWorker();
}
);
}

/* =========================================================
DOM VALIDATION
========================================================= */

function validateDom() {
const requiredElements = [
['inputText', inputElement],
['outputText', outputElement],
['fileInput', fileInput],
['clearButton', clearButton],
['sanitizeButton', sanitizeButton],
['copyButton', copyButton],
['downloadButton', downloadButton],
['strictMode', strictMode],
['profileSelect', profileSelect],
['statusPanel', statusPanel],
['statusText', statusText],
['progressPercent', progressPercent],
['progressBar', progressBar],
['errorPanel', errorPanel],
['errorText', errorText],
['inputSize', inputSize],
['outputSize', outputSize],
['outputStatus', outputStatus],
['rulesMatched', rulesMatched],
['totalMatches', totalMatches],
['statsInputSize', statsInputSize],
['statsOutputSize', statsOutputSize],
['matchedRules', matchedRules],
['matchedRulesList', matchedRulesList]
];

const missing =
requiredElements
.filter(([, element]) => !element)
.map(([id]) => id);

if (missing.length > 0) {
throw new Error(
`SanitizeLog UI initialization failed. Missing elements: ${missing.join(', ')}`
);
}
}

/* =========================================================
PROFILES
========================================================= */

function populateProfiles() {
profileSelect.replaceChildren();

for (const profile of Object.values(PROFILES)) {
const option =
document.createElement('option');

```
option.value = profile.id;

option.textContent = profile.name;

profileSelect.appendChild(option);
```

}
}

/* =========================================================
WORKER MANAGEMENT
========================================================= */

function createWorker() {
terminateWorker();

worker = new Worker(
'./sanitizer.worker.js',
{
type: 'classic'
}
);

worker.addEventListener(
'message',
handleWorkerMessage
);

worker.addEventListener(
'error',
handleWorkerError
);

return worker;
}

function terminateWorker() {
if (worker) {
worker.terminate();
worker = null;
}
}

function handleWorkerError(event) {
const message =
event?.message ||
'The sanitization worker encountered an unexpected error.';

handleError(message);
}

/* =========================================================
WORKER MESSAGE HANDLING
========================================================= */

function handleWorkerMessage(event) {
const message =
event.data || {};

switch (message.type) {
case 'PROGRESS':
handleProgress(message.payload);
break;

```
case 'COMPLETE':
  handleComplete(message.payload);
  break;

case 'COMPLETE_BLOB':
  handleCompleteBlob(message.payload);
  break;

case 'ERROR':
  handleError(message.error);
  break;

case 'CANCELLED':
  handleCancelled();
  break;

default:
  handleError(
    `Unexpected worker message type '${message.type}'.`
  );
  break;
```

}
}

/* =========================================================
PROGRESS
========================================================= */

function handleProgress(payload) {
if (!payload) {
return;
}

const processedBytes =
Number.isFinite(payload.processedBytes)
? payload.processedBytes
: 0;

const totalBytes =
Number.isFinite(payload.totalBytes)
? payload.totalBytes
: 0;

let percent =
Number.isFinite(payload.percent)
? payload.percent
: 0;

percent =
Math.max(
0,
Math.min(100, percent)
);

setProgress(percent);

setStatus(
'Sanitizing',
`Processed ${formatBytes(processedBytes)} of ${formatBytes(totalBytes)}.`
);
}

/* =========================================================
COMPLETE: TEXT INPUT
========================================================= */

function handleComplete(payload) {
if (!payload) {
handleError(
'Worker returned an invalid COMPLETE payload.'
);
return;
}

const sanitizedText =
String(
payload.sanitizedText ?? ''
);

const outputBytes =
getUtf8ByteLength(sanitizedText);

const blob =
new Blob(
[sanitizedText],
{
type: 'text/plain;charset=utf-8'
}
);

finishSanitization({
outputTextValue: sanitizedText,
outputBlob: blob,
outputBytes,
stats:
payload.stats || {
matches: {}
}
});
}

/* =========================================================
COMPLETE: BLOB INPUT
========================================================= */

async function handleCompleteBlob(payload) {
if (
!payload ||
!(payload.blob instanceof Blob)
) {
handleError(
'Worker returned an invalid COMPLETE_BLOB payload.'
);
return;
}

const outputBlob =
payload.blob;

const outputBytes =
outputBlob.size;

/*

* Do not call blob.text() for large files.
*
* This would create a potentially 500 MB JavaScript
* string and defeat the large-file architecture.
  */
  let displayText = '';

if (
outputBytes <=
MAX_DISPLAY_OUTPUT_BYTES
) {
try {
displayText =
await outputBlob.text();
} catch (error) {
handleError(
error instanceof Error
? error.message
: String(error)
);
return;
}
}

finishSanitization({
outputTextValue: displayText,
outputBlob,
outputBytes,
stats:
payload.stats || {
matches: {}
}
});
}

/* =========================================================
FINISH
========================================================= */

function finishSanitization({
outputTextValue,
outputBlob,
outputBytes,
stats
}) {
lastOutputText =
outputTextValue || '';

lastOutputBlob =
outputBlob || null;

lastOutputBytes =
Number.isFinite(outputBytes)
? outputBytes
: 0;

const inputBytes =
getCurrentInputBytes();

lastInputBytes =
inputBytes;

outputElement.value =
lastOutputText;

inputSize.textContent =
formatBytes(inputBytes);

outputSize.textContent =
formatBytes(lastOutputBytes);

statsInputSize.textContent =
formatBytes(inputBytes);

statsOutputSize.textContent =
formatBytes(lastOutputBytes);

updateStatistics(stats);

setProgress(100);

setStatus(
'Completed',
'Sanitization completed successfully.'
);

if (
lastOutputBytes >
MAX_DISPLAY_OUTPUT_BYTES
) {
outputStatus.textContent =
`Large output ready for download. ` +
`Preview is disabled above ${formatMB(MAX_DISPLAY_OUTPUT_BYTES)}.`;
} else if (lastOutputBytes > 0) {
outputStatus.textContent =
'Sanitized output is ready.';
} else {
outputStatus.textContent =
'Sanitization completed with empty output.';
}

copyButton.disabled =
lastOutputText.length === 0;

downloadButton.disabled =
!lastOutputBlob ||
lastOutputBytes === 0;

sanitizeButton.disabled =
false;

terminateWorker();
}

/* =========================================================
ERROR
========================================================= */

function handleError(message) {
const errorMessage =
message ||
'Sanitization failed.';

errorPanel.hidden = false;

errorText.textContent =
errorMessage;

setStatus(
'Failed',
'The sanitization operation failed.'
);

setProgress(0);

lastOutputText =
'';

lastOutputBlob =
null;

lastOutputBytes =
0;

outputElement.value =
'';

outputSize.textContent =
'0 B';

statsOutputSize.textContent =
'0 B';

outputStatus.textContent =
'No output generated';

copyButton.disabled =
true;

downloadButton.disabled =
true;

sanitizeButton.disabled =
false;

terminateWorker();
}

/* =========================================================
CANCELLED
========================================================= */

function handleCancelled() {
errorPanel.hidden = true;

setStatus(
'Cancelled',
'The sanitization operation was cancelled.'
);

setProgress(0);

lastOutputText =
'';

lastOutputBlob =
null;

lastOutputBytes =
0;

outputElement.value =
'';

outputSize.textContent =
'0 B';

statsOutputSize.textContent =
'0 B';

outputStatus.textContent =
'No output generated';

copyButton.disabled =
true;

downloadButton.disabled =
true;

sanitizeButton.disabled =
false;

terminateWorker();
}

/* =========================================================
SANITIZATION
========================================================= */

function sanitize() {
hideError();

const profile =
PROFILES[
profileSelect.value
];

if (!profile) {
handleError(
'Selected security profile was not found.'
);
return;
}

const hasSelectedFile =
selectedFile instanceof File;

const content =
hasSelectedFile
? selectedFile
: inputElement.value;

if (
!hasSelectedFile &&
!content
) {
handleError(
'Enter diagnostic content or select a file before sanitizing.'
);
return;
}

if (hasSelectedFile) {
const validation =
validateSelectedFile(
selectedFile
);

```
if (!validation.valid) {
  handleError(
    validation.message
  );
  return;
}
```

}

resetOutputForProcessing();

sanitizeButton.disabled =
true;

setProgress(0);

setStatus(
'Starting',
hasSelectedFile
? `Preparing ${selectedFile.name} for local streaming sanitization...`
: 'Initializing local sanitization...'
);

try {
const activeWorker =
createWorker();

```
activeWorker.postMessage({
  type: 'START',

  payload: {
    content,

    rules:
      profile.rules,

    options: {
      strict:
        Boolean(
          strictMode.checked
        )
    }
  }
});
```

} catch (error) {
handleError(
error instanceof Error
? error.message
: String(error)
);
}
}

/* =========================================================
FILE VALIDATION
========================================================= */

function validateSelectedFile(file) {
if (!(file instanceof File)) {
return {
valid: false,
message:
'The selected file is invalid.'
};
}

if (file.size > MAX_FILE_BYTES) {
return {
valid: false,
message:
`The selected file is too large. ` +
`The maximum supported file size is ${MAX_FILE_MB} MB. ` +
`Selected size: ${formatBytes(file.size)}.`
};
}

const fileName =
file.name.toLowerCase();

const supported =
SUPPORTED_FILE_EXTENSIONS.some(
(extension) =>
fileName.endsWith(extension)
);

if (!supported) {
return {
valid: false,
message:
'Unsupported file format. Supported formats are TXT, LOG, CONF, CFG, CONFIG, OUT, JSON, YAML, YML, XML, CSV and INI.'
};
}

return {
valid: true,
message: ''
};
}

/* =========================================================
FILE SELECTION
========================================================= */

function handleFileSelection(event) {
const file =
event.target.files?.[0];

if (!file) {
return;
}

hideError();

const validation =
validateSelectedFile(file);

if (!validation.valid) {
selectedFile = null;

```
fileInput.value = '';

handleError(
  validation.message
);

return;
```

}

terminateWorker();

selectedFile =
file;

selectedFileName =
buildOutputFileName(
file.name
);

/*

* Do not read the file into inputElement.value.
*
* That would convert a 500 MB file into a huge
* JavaScript string before the worker starts.
  */

inputElement.value = '';

lastOutputText =
'';

lastOutputBlob =
null;

lastOutputBytes =
0;

lastInputBytes =
file.size;

inputSize.textContent =
formatBytes(file.size);

outputSize.textContent =
'0 B';

statsInputSize.textContent =
formatBytes(file.size);

statsOutputSize.textContent =
'0 B';

outputElement.value =
'';

outputStatus.textContent =
'No output generated';

updateStatistics({
matches: {}
});

setProgress(0);

setStatus(
'Ready',
`${file.name} selected. ${formatBytes(file.size)} will be processed locally.`
);

copyButton.disabled =
true;

downloadButton.disabled =
true;

sanitizeButton.disabled =
false;
}

/* =========================================================
INPUT CHANGES
========================================================= */

function handleInputChange() {
/*

* If the user starts typing/pasting after selecting
* a file, the text becomes the active input source.
  */
  if (inputElement.value.length > 0) {
  selectedFile = null;

```
fileInput.value = '';
```

```
selectedFileName =
  'sanitized-output.txt';
```

}

updateInputSize();

if (!inputElement.value) {
setStatus(
'Ready',
selectedFile
? `${selectedFile.name} selected.`
: 'Add diagnostic content or load a local file.'
);
}
}

/* =========================================================
CLEAR
========================================================= */

function clearInput() {
terminateWorker();

selectedFile =
null;

selectedFileName =
'sanitized-output.txt';

lastOutputText =
'';

lastOutputBlob =
null;

lastInputBytes =
0;

lastOutputBytes =
0;

inputElement.value =
'';

outputElement.value =
'';

fileInput.value =
'';

inputSize.textContent =
'0 B';

outputSize.textContent =
'0 B';

statsInputSize.textContent =
'0 B';

statsOutputSize.textContent =
'0 B';

outputStatus.textContent =
'No output generated';

updateStatistics({
matches: {}
});

hideError();

setProgress(0);

setStatus(
'Ready',
'Add diagnostic content or load a local file.'
);

copyButton.disabled =
true;

downloadButton.disabled =
true;

sanitizeButton.disabled =
false;
}

/* =========================================================
OUTPUT RESET
========================================================= */

function resetOutputForProcessing() {
lastOutputText =
'';

lastOutputBlob =
null;

lastOutputBytes =
0;

outputElement.value =
'';

outputSize.textContent =
'0 B';

statsOutputSize.textContent =
'0 B';

outputStatus.textContent =
'Processing...';

updateStatistics({
matches: {}
});

copyButton.disabled =
true;

downloadButton.disabled =
true;
}

/* =========================================================
COPY
========================================================= */

async function copyOutput() {
if (!lastOutputText) {
return;
}

try {
await navigator.clipboard.writeText(
lastOutputText
);

```
setStatus(
  'Completed',
  'Sanitized output copied to the clipboard.'
);
```

} catch {
try {
outputElement.focus();

```
  outputElement.select();

  const copied =
    document.execCommand(
      'copy'
    );

  setStatus(
    'Completed',
    copied
      ? 'Sanitized output copied to the clipboard.'
      : 'Clipboard access was not available. Select and copy the output manually.'
  );
} catch {
  setStatus(
    'Completed',
    'Clipboard access was not available. Select and copy the output manually.'
  );
}
```

}
}

/* =========================================================
DOWNLOAD
========================================================= */

function downloadOutput() {
if (
!lastOutputBlob ||
lastOutputBytes === 0
) {
return;
}

const url =
URL.createObjectURL(
lastOutputBlob
);

const anchor =
document.createElement('a');

anchor.href =
url;

anchor.download =
selectedFileName;

document.body.appendChild(
anchor
);

anchor.click();

anchor.remove();

/*

* Delay revocation slightly so the browser has
* sufficient time to begin the download.
  */
  setTimeout(() => {
  URL.revokeObjectURL(url);
  }, 1000);

setStatus(
'Completed',
'Sanitized output downloaded locally.'
);
}

/* =========================================================
STATISTICS
========================================================= */

function updateStatistics(stats) {
const matches =
stats &&
stats.matches &&
typeof stats.matches === 'object'
? stats.matches
: {};

const entries =
Object.entries(matches)
.filter(
([, count]) =>
Number.isFinite(count) &&
count > 0
);

const matchedRuleCount =
entries.length;

const totalMatchCount =
entries.reduce(
(total, [, count]) =>
total + count,
0
);

rulesMatched.textContent =
String(
matchedRuleCount
);

totalMatches.textContent =
String(
totalMatchCount
);

matchedRules.hidden =
entries.length === 0;

matchedRulesList.replaceChildren();

if (entries.length === 0) {
return;
}

for (
const [ruleId, count]
of entries
) {
const row =
document.createElement(
'li'
);

```
const name =
  document.createElement(
    'span'
  );

name.className =
  'matched-rule-name';

name.textContent =
  ruleId;

const countElement =
  document.createElement(
    'span'
  );

countElement.className =
  'matched-rule-count';

countElement.textContent =
  `${count} match${
    count === 1
      ? ''
      : 'es'
  }`;

row.append(
  name,
  countElement
);

matchedRulesList.appendChild(
  row
);
```

}
}

/* =========================================================
INPUT / OUTPUT SIZES
========================================================= */

function updateInputSize() {
const bytes =
getCurrentInputBytes();

lastInputBytes =
bytes;

inputSize.textContent =
formatBytes(bytes);

statsInputSize.textContent =
formatBytes(bytes);
}

function getCurrentInputBytes() {
if (selectedFile) {
return selectedFile.size;
}

return getUtf8ByteLength(
inputElement.value
);
}

/* =========================================================
STATUS
========================================================= */

function setStatus(
label,
message
) {
statusText.textContent =
label;

/*

* The current HTML contains only statusText
* and progressPercent inside the status panel.
*
* Keep the detailed message available through
* the accessible status text without requiring
* an additional DOM element.
  */
  statusPanel.setAttribute(
  'aria-label',
  `${label}. ${message}`
  );
  }

function setProgress(percent) {
const safePercent =
Math.max(
0,
Math.min(
100,
Number.isFinite(percent)
? percent
: 0
)
);

progressBar.style.width =
`${safePercent}%`;

progressBar.setAttribute(
'aria-valuenow',
String(safePercent)
);

progressPercent.textContent =
`${safePercent}%`;
}

/* =========================================================
ERROR UI
========================================================= */

function hideError() {
errorPanel.hidden =
true;

errorText.textContent =
'';
}

/* =========================================================
BYTE / SIZE UTILITIES
========================================================= */

function getUtf8ByteLength(text) {
return new TextEncoder()
.encode(
String(
text ?? ''
)
)
.byteLength;
}

function formatBytes(bytes) {
if (
!Number.isFinite(bytes) ||
bytes <= 0
) {
return '0 B';
}

if (bytes < 1024) {
return `${Math.round(bytes)} B`;
}

if (
bytes <
1024 * 1024
) {
return `${(
      bytes / 1024
    ).toFixed(1)} KB`;
}

if (
bytes <
1024 * 1024 * 1024
) {
return `${(
      bytes /
      (1024 * 1024)
    ).toFixed(1)} MB`;
}

return `${(
    bytes /
    (1024 * 1024 * 1024)
  ).toFixed(2)} GB`;
}

function formatMB(bytes) {
return Math.round(
bytes /
(1024 * 1024)
) + ' MB';
}

/* =========================================================
FILE NAME
========================================================= */

function buildOutputFileName(
fileName
) {
if (
typeof fileName !== 'string' ||
fileName.length === 0
) {
return 'sanitized-output.txt';
}

const dotIndex =
fileName.lastIndexOf('.');

if (
dotIndex <= 0
) {
return `${fileName}-sanitized.txt`;
}

const base =
fileName.slice(
0,
dotIndex
);

const extension =
fileName.slice(
dotIndex
);

return `${base}-sanitized${extension}`;
}
