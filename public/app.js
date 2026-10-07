const inputElement =
document.getElementById('input');

const outputElement =
document.getElementById('output');

const fileInput =
document.getElementById('file-input');

const clearButton =
document.getElementById('clear-button');

const sanitizeButton =
document.getElementById('sanitize-button');

const copyButton =
document.getElementById('copy-button');

const downloadButton =
document.getElementById('download-button');

const strictMode =
document.getElementById('strict-mode');

const profileSelect =
document.getElementById('profile-select');

const inputSize =
document.getElementById('input-size');

const outputSize =
document.getElementById('output-size');

const resultInputSize =
document.getElementById(
'result-input-size'
);

const resultOutputSize =
document.getElementById(
'result-output-size'
);

const rulesMatched =
document.getElementById(
'rules-matched'
);

const totalMatches =
document.getElementById(
'total-matches'
);

const matchList =
document.getElementById(
'match-list'
);

const statusLabel =
document.getElementById(
'status-label'
);

const statusMessage =
document.getElementById(
'status-message'
);

const progressLabel =
document.getElementById(
'progress-label'
);

const progressBar =
document.getElementById(
'progress-bar'
);

let worker = null;
let lastOutput = '';
let selectedFileName = 'sanitized-output.txt';

const COMMON_RULES = [
{
id: 'common-jwt',
description: 'JSON Web Token (JWT)',
scope: 'line',
regex:
/bearer\s+(eyJ[a-zA-Z0-9_-]+.eyJ[a-zA-Z0-9_-]+.[a-zA-Z0-9_.-]+)/gi,
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
name:
'Default Security Baseline',
description:
'Standard security detection profile',
rules: COMMON_RULES
}
};

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

function handleWorkerMessage(event) {
const message =
event.data || {};

switch (message.type) {
case 'PROGRESS':
handleProgress(
message.payload
);
break;

```
case 'COMPLETE':
  handleComplete(
    message.payload
  );
  break;

case 'COMPLETE_BLOB':
  handleCompleteBlob(
    message.payload
  );
  break;

case 'ERROR':
  handleError(
    message.error
  );
  break;

case 'CANCELLED':
  handleCancelled();
  break;

default:
  break;
```

}
}

function handleProgress(payload) {
if (!payload) {
return;
}

const percent =
Number.isFinite(
payload.percent
)
? payload.percent
: 0;

progressBar.style.width =
`${percent}%`;

progressBar.setAttribute(
'aria-valuenow',
String(percent)
);

progressLabel.textContent =
`${percent}%`;

statusLabel.textContent =
'Sanitizing';

statusMessage.textContent =
`Processed ${formatBytes(
      payload.processedBytes || 0
    )} of ${formatBytes(
      payload.totalBytes || 0
    )}.`;
}

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

finishSanitization(
sanitizedText,
payload.stats || {
matches: {}
}
);
}

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

try {
const text =
await payload.blob.text();

```
finishSanitization(
  text,
  payload.stats || {
    matches: {}
  }
);
```

} catch (error) {
handleError(
error instanceof Error
? error.message
: String(error)
);
}
}

function finishSanitization(
sanitizedText,
stats
) {
lastOutput =
sanitizedText;

outputElement.value =
sanitizedText;

const inputText =
inputElement.value;

const inputBytes =
getUtf8ByteLength(
inputText
);

const outputBytes =
getUtf8ByteLength(
sanitizedText
);

inputSize.textContent =
formatBytes(inputBytes);

outputSize.textContent =
formatBytes(outputBytes);

resultInputSize.textContent =
formatBytes(inputBytes);

resultOutputSize.textContent =
formatBytes(outputBytes);

updateStatistics(
stats
);

progressBar.style.width =
'100%';

progressBar.setAttribute(
'aria-valuenow',
'100'
);

progressLabel.textContent =
'100%';

statusLabel.textContent =
'Completed';

statusMessage.textContent =
'Sanitization completed successfully.';

copyButton.disabled =
sanitizedText.length === 0;

downloadButton.disabled =
sanitizedText.length === 0;

sanitizeButton.disabled =
false;

terminateWorker();
}

function handleError(message) {
statusLabel.textContent =
'Failed';

statusMessage.textContent =
message ||
'Sanitization failed.';

progressBar.style.width =
'0%';

progressBar.setAttribute(
'aria-valuenow',
'0'
);

progressLabel.textContent =
'0%';

copyButton.disabled =
true;

downloadButton.disabled =
true;

sanitizeButton.disabled =
false;

lastOutput = '';

outputElement.value = '';

terminateWorker();
}

function handleCancelled() {
statusLabel.textContent =
'Cancelled';

statusMessage.textContent =
'The sanitization operation was cancelled.';

sanitizeButton.disabled =
false;

copyButton.disabled =
true;

downloadButton.disabled =
true;

terminateWorker();
}

async function sanitize() {
const content =
inputElement.value;

if (!content) {
statusLabel.textContent =
'Ready';

```
statusMessage.textContent =
  'Enter diagnostic content before sanitizing.';

return;
```

}

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

outputElement.value = '';
lastOutput = '';

copyButton.disabled = true;
downloadButton.disabled = true;
sanitizeButton.disabled = true;

progressBar.style.width =
'0%';

progressBar.setAttribute(
'aria-valuenow',
'0'
);

progressLabel.textContent =
'0%';

statusLabel.textContent =
'Starting';

statusMessage.textContent =
'Initializing local sanitization...';

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
        strictMode.checked
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

if (entries.length === 0) {
matchList.className =
'match-list empty';

```
matchList.textContent =
  'No configured rules matched the input.';

return;
```

}

matchList.className =
'match-list';

matchList.replaceChildren();

for (
const [ruleId, count]
of entries
) {
const row =
document.createElement(
'div'
);

```
row.className =
  'match-row';

const name =
  document.createElement(
    'span'
  );

name.className =
  'match-name';

name.textContent =
  ruleId;

const countElement =
  document.createElement(
    'span'
  );

countElement.className =
  'match-count';

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

matchList.append(
  row
);
```

}
}

function updateInputSize() {
const bytes =
getUtf8ByteLength(
inputElement.value
);

inputSize.textContent =
formatBytes(bytes);
}

function clearInput() {
terminateWorker();

inputElement.value = '';
outputElement.value = '';

lastOutput = '';

inputSize.textContent =
'0 bytes';

outputSize.textContent =
'0 bytes';

resultInputSize.textContent =
'0 B';

resultOutputSize.textContent =
'0 B';

rulesMatched.textContent =
'0';

totalMatches.textContent =
'0';

matchList.className =
'match-list empty';

matchList.textContent =
'No rules have matched yet.';

progressBar.style.width =
'0%';

progressBar.setAttribute(
'aria-valuenow',
'0'
);

progressLabel.textContent =
'0%';

statusLabel.textContent =
'Ready';

statusMessage.textContent =
'Add diagnostic content and start sanitization.';

copyButton.disabled =
true;

downloadButton.disabled =
true;

sanitizeButton.disabled =
false;

selectedFileName =
'sanitized-output.txt';

fileInput.value = '';
}

async function loadFile(event) {
const file =
event.target.files &&
event.target.files[0];

if (!file) {
return;
}

try {
const text =
await file.text();

```
inputElement.value =
  text;

selectedFileName =
  buildOutputFileName(
    file.name
  );

updateInputSize();

statusLabel.textContent =
  'Ready';

statusMessage.textContent =
  `${file.name} loaded locally.`;

outputElement.value = '';
lastOutput = '';

copyButton.disabled =
  true;

downloadButton.disabled =
  true;
```

} catch (error) {
statusLabel.textContent =
'Failed';

```
statusMessage.textContent =
  error instanceof Error
    ? error.message
    : String(error);
```

} finally {
fileInput.value = '';
}
}

async function copyOutput() {
if (!lastOutput) {
return;
}

try {
await navigator.clipboard.writeText(
lastOutput
);

```
statusMessage.textContent =
  'Sanitized output copied to the clipboard.';
```

} catch {
outputElement.focus();
outputElement.select();

```
const copied =
  document.execCommand(
    'copy'
  );

statusMessage.textContent =
  copied
    ? 'Sanitized output copied to the clipboard.'
    : 'Clipboard access was not available. Select and copy the output manually.';
```

}
}

function downloadOutput() {
if (!lastOutput) {
return;
}

const blob =
new Blob(
[lastOutput],
{
type: 'text/plain;charset=utf-8'
}
);

const url =
URL.createObjectURL(
blob
);

const anchor =
document.createElement(
'a'
);

anchor.href = url;
anchor.download =
selectedFileName;

document.body.append(
anchor
);

anchor.click();

anchor.remove();

URL.revokeObjectURL(
url
);

statusMessage.textContent =
'Sanitized output downloaded locally.';
}

function getUtf8ByteLength(text) {
return new TextEncoder()
.encode(
String(text ?? '')
)
.byteLength;
}

function formatBytes(bytes) {
if (!Number.isFinite(bytes)) {
return '0 B';
}

if (bytes < 1024) {
return `${bytes} B`;
}

if (bytes < 1024 * 1024) {
return `${(
      bytes / 1024
    ).toFixed(1)} KB`;
}

if (bytes < 1024 * 1024 * 1024) {
return `${(
      bytes /
      (1024 * 1024)
    ).toFixed(1)} MB`;
}

return `${(
    bytes /
    (1024 * 1024 * 1024)
  ).toFixed(1)} GB`;
}

function buildOutputFileName(
fileName
) {
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

inputElement.addEventListener(
'input',
updateInputSize
);

clearButton.addEventListener(
'click',
clearInput
);

sanitizeButton.addEventListener(
'click',
sanitize
);

fileInput.addEventListener(
'change',
loadFile
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

updateInputSize();
