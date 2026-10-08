import { TypeAwareTokenMap } from './token-map.js';
import { applyReplacement } from './replacement.js';
import { validateRules } from './rule-validator.js';

const MAX_FILE_BYTES = 500 * 1024 * 1024;
const DEFAULT_MAX_BLOCK_BYTES = 1048576;

let currentAbortController = null;

self.onmessage = async (event) => {
const { data, postMessage } = parseWorkerEvent(event);

if (!data || !data.type) {
return;
}

if (data.type === 'CANCEL') {
if (currentAbortController) {
currentAbortController.abort();
}


return;


}

if (data.type !== 'START') {
dispatchMessage(postMessage, {
type: 'ERROR',
error: "Unsupported worker message type '" + data.type + "'."
});


return;


}

currentAbortController = new AbortController();

const signal = currentAbortController.signal;

try {
const { content, rules, options = {} } = data.payload || {};


validateRules(rules);

const tokenMap = new TypeAwareTokenMap(
  options.tokenMapState
);

const stats = {
  matches: {}
};

const isBlobInput =
  typeof Blob !== 'undefined' &&
  content instanceof Blob;

if (isBlobInput) {
  await processBlobContent({
    blob: content,
    rules,
    options,
    tokenMap,
    stats,
    signal,
    postMessage
  });
} else {
  await processTextContent({
    textInput: String(content ?? ''),
    rules,
    options,
    tokenMap,
    stats,
    signal,
    postMessage
  });
}


} catch (err) {
if (signal.aborted) {
dispatchMessage(postMessage, {
type: 'CANCELLED'
});
} else {
dispatchMessage(postMessage, {
type: 'ERROR',
error:
err instanceof Error
? err.message
: String(err)
});
}
} finally {
currentAbortController = null;
}
};

function parseWorkerEvent(event) {
const data = event.data || event;

const postMessage = event.postMessage
? event.postMessage
: (message) => self.postMessage(message);

return {
data,
postMessage
};
}

function dispatchMessage(postFn, message) {
postFn(message);
}

async function processBlobContent({
blob,
rules,
options,
tokenMap,
stats,
signal,
postMessage
}) {
if (blob.size > MAX_FILE_BYTES) {
throw new Error(
'Input file exceeds the maximum supported size of ' +
formatMB(MAX_FILE_BYTES) +
'.'
);
}

if (blob.size === 0) {
dispatchMessage(postMessage, {
type: 'PROGRESS',
payload: {
processedBytes: 0,
totalBytes: 0,
percent: 100
}
});


dispatchMessage(postMessage, {
  type: 'COMPLETE_BLOB',
  payload: {
    blob: new Blob([''], {
      type: blob.type || 'text/plain'
    }),
    stats
  }
});

return;


}

if (
typeof blob.stream !== 'function' ||
typeof TextDecoderStream === 'undefined'
) {
throw new Error(
'This browser does not support the streaming APIs required for large-file sanitization.'
);
}

const lineRules = rules.filter(
(rule) => (rule.scope ?? 'line') !== 'block'
);

const blockRules = rules.filter(
(rule) => rule.scope === 'block'
);

const outputChunks = [];

const reader = blob
.stream()
.pipeThrough(
new TextDecoderStream('utf-8')
)
.getReader();

let processedBytes = 0;
let textBuffer = '';

let activeBlockRule = null;
let activeBlockBuffer = '';
let activeBlockBytes = 0;

while (true) {
if (signal.aborted) {
try {
await reader.cancel();
} catch {
// Best-effort stream cancellation.
}


  throw new Error('Operation cancelled');
}

const result = await reader.read();

if (result.done) {
  break;
}

if (typeof result.value !== 'string') {
  throw new Error(
    'Streaming decoder returned invalid text data.'
  );
}

textBuffer += result.value;

processedBytes += new TextEncoder()
  .encode(result.value)
  .byteLength;

const extracted =
  extractCompleteLines(textBuffer);

textBuffer = extracted.remaining;

for (const line of extracted.lines) {
  if (signal.aborted) {
    try {
      await reader.cancel();
    } catch {
      // Best-effort stream cancellation.
    }

    throw new Error('Operation cancelled');
  }

  const processed = processLine(
    line.rawLine,
    line.lineEnding,
    lineRules,
    blockRules,
    {
      activeBlockRule,
      activeBlockBuffer,
      activeBlockBytes
    },
    tokenMap,
    stats
  );

  activeBlockRule =
    processed.activeBlockRule;

  activeBlockBuffer =
    processed.activeBlockBuffer;

  activeBlockBytes =
    processed.activeBlockBytes;

  if (processed.output !== null) {
    outputChunks.push(processed.output);
  }
}

dispatchProgress(
  postMessage,
  processedBytes,
  blob.size
);


}

if (textBuffer.length > 0) {
const processed = processLine(
textBuffer,
'',
lineRules,
blockRules,
{
activeBlockRule,
activeBlockBuffer,
activeBlockBytes
},
tokenMap,
stats
);


activeBlockRule =
  processed.activeBlockRule;

activeBlockBuffer =
  processed.activeBlockBuffer;

activeBlockBytes =
  processed.activeBlockBytes;

if (processed.output !== null) {
  outputChunks.push(processed.output);
}


}

if (activeBlockRule) {
if (options.strict) {
throw new Error(
"Unterminated block detected for rule '" +
activeBlockRule.id +
"' at EOF."
);
}


outputChunks.push(activeBlockBuffer);


}

if (signal.aborted) {
throw new Error('Operation cancelled');
}

const outputBlob = new Blob(
outputChunks,
{
type: blob.type || 'text/plain'
}
);

dispatchMessage(postMessage, {
type: 'PROGRESS',
payload: {
processedBytes: blob.size,
totalBytes: blob.size,
percent: 100
}
});

dispatchMessage(postMessage, {
type: 'COMPLETE_BLOB',
payload: {
blob: outputBlob,
stats
}
});
}

async function processTextContent({
textInput,
rules,
options,
tokenMap,
stats,
signal,
postMessage
}) {
const totalBytes =
new TextEncoder()
.encode(textInput)
.byteLength;

if (totalBytes === 0) {
dispatchMessage(postMessage, {
type: 'PROGRESS',
payload: {
processedBytes: 0,
totalBytes: 0,
percent: 100
}
});


dispatchMessage(postMessage, {
  type: 'COMPLETE',
  payload: {
    sanitizedText: '',
    stats
  }
});

return;


}

if (totalBytes > MAX_FILE_BYTES) {
throw new Error(
'Input text exceeds the maximum supported size of ' +
formatMB(MAX_FILE_BYTES) +
'.'
);
}

const lineRules = rules.filter(
(rule) => (rule.scope ?? 'line') !== 'block'
);

const blockRules = rules.filter(
(rule) => rule.scope === 'block'
);

const sanitizedText = await processContent({
textInput,
totalBytes,
lineRules,
blockRules,
tokenMap,
stats,
strict: Boolean(options.strict),
signal,
postMessage
});

if (signal.aborted) {
dispatchMessage(postMessage, {
type: 'CANCELLED'
});


return;


}

dispatchMessage(postMessage, {
type: 'COMPLETE',
payload: {
sanitizedText,
stats
}
});
}

async function processContent({
textInput,
totalBytes,
lineRules,
blockRules,
tokenMap,
stats,
strict,
signal,
postMessage
}) {
const lines =
splitLinesWithEndings(textInput);

const outputLines = [];

let processedBytes = 0;

let activeBlockRule = null;
let activeBlockBuffer = '';
let activeBlockBytes = 0;

for (const line of lines) {
if (signal.aborted) {
throw new Error('Operation cancelled');
}


const result = processLine(
  line.rawLine,
  line.lineEnding,
  lineRules,
  blockRules,
  {
    activeBlockRule,
    activeBlockBuffer,
    activeBlockBytes
  },
  tokenMap,
  stats
);

activeBlockRule =
  result.activeBlockRule;

activeBlockBuffer =
  result.activeBlockBuffer;

activeBlockBytes =
  result.activeBlockBytes;

if (result.output !== null) {
  outputLines.push(result.output);
}

processedBytes += new TextEncoder()
  .encode(
    line.rawLine +
    line.lineEnding
  )
  .byteLength;

dispatchProgress(
  postMessage,
  processedBytes,
  totalBytes
);


}

if (activeBlockRule) {
if (strict) {
throw new Error(
"Unterminated block detected for rule '" +
activeBlockRule.id +
"' at EOF."
);
}


outputLines.push(activeBlockBuffer);


}

return outputLines.join('');
}

function processLine(
rawLine,
lineEnding,
lineRules,
blockRules,
blockState,
tokenMap,
stats
) {
let activeBlockRule =
blockState.activeBlockRule;

let activeBlockBuffer =
blockState.activeBlockBuffer;

let activeBlockBytes =
blockState.activeBlockBytes;

const lineByteCount =
new TextEncoder()
.encode(
rawLine +
lineEnding
)
.byteLength;

if (activeBlockRule) {
const maxAllowedBytes =
activeBlockRule.maxBytes ??
DEFAULT_MAX_BLOCK_BYTES;


activeBlockBytes +=
  lineByteCount;

if (
  activeBlockBytes >
  maxAllowedBytes
) {
  throw new Error(
    "Rule '" +
    activeBlockRule.id +
    "' exceeded maxBytes limit of " +
    maxAllowedBytes +
    ' bytes.'
  );
}

activeBlockBuffer +=
  rawLine +
  lineEnding;

if (
  testRegex(
    activeBlockRule.endRegex,
    rawLine
  )
) {
  const output =
    applyBlockReplacement(
      activeBlockRule,
      activeBlockBuffer,
      tokenMap,
      stats
    );

  return {
    output,
    activeBlockRule: null,
    activeBlockBuffer: '',
    activeBlockBytes: 0
  };
}

return {
  output: null,
  activeBlockRule,
  activeBlockBuffer,
  activeBlockBytes
};


}

for (const blockRule of blockRules) {
if (
!testRegex(
blockRule.startRegex,
rawLine
)
) {
continue;
}


activeBlockRule =
  blockRule;

activeBlockBuffer =
  rawLine +
  lineEnding;

activeBlockBytes =
  lineByteCount;

const maxAllowedBytes =
  blockRule.maxBytes ??
  DEFAULT_MAX_BLOCK_BYTES;

if (
  activeBlockBytes >
  maxAllowedBytes
) {
  throw new Error(
    "Rule '" +
    blockRule.id +
    "' exceeded maxBytes limit of " +
    maxAllowedBytes +
    ' bytes.'
  );
}

if (
  testRegex(
    blockRule.endRegex,
    rawLine
  )
) {
  const output =
    applyBlockReplacement(
      blockRule,
      activeBlockBuffer,
      tokenMap,
      stats
    );

  return {
    output,
    activeBlockRule: null,
    activeBlockBuffer: '',
    activeBlockBytes: 0
  };
}

return {
  output: null,
  activeBlockRule,
  activeBlockBuffer,
  activeBlockBytes
};


}

let currentLine = rawLine;

for (const rule of lineRules) {
currentLine =
executeLineRule(
rule,
currentLine,
tokenMap,
stats
);
}

return {
output:
currentLine +
lineEnding,
activeBlockRule: null,
activeBlockBuffer: '',
activeBlockBytes: 0
};
}

function executeLineRule(
rule,
text,
tokenMap,
stats
) {
const regex =
new RegExp(
rule.regex.source,
rule.regex.flags
);

return text.replace(
regex,
(...args) => {
const match =
args[0];


  const captureGroups =
    args
      .slice(1, args.length - 2)
      .map(
        (group) =>
          group === undefined
            ? ''
            : group
      );

  return applyReplacement(
    rule,
    match,
    captureGroups,
    tokenMap,
    stats
  );
}


);
}

function applyBlockReplacement(
rule,
blockBuffer,
tokenMap,
stats
) {
return applyReplacement(
rule,
blockBuffer,
[],
tokenMap,
stats
);
}

function testRegex(
regex,
value
) {
const safeRegex =
new RegExp(
regex.source,
regex.flags
);

safeRegex.lastIndex = 0;

return safeRegex.test(value);
}

function extractCompleteLines(
buffer
) {
const lines = [];

let start = 0;

for (
let index = 0;
index < buffer.length;
index++
) {
const character =
buffer[index];


if (character === '\n') {
  lines.push({
    rawLine:
      buffer.slice(
        start,
        index
      ),
    lineEnding: '\n'
  });

  start =
    index + 1;

  continue;
}

if (character === '\r') {
  if (
    index + 1 <
      buffer.length &&
    buffer[index + 1] === '\n'
  ) {
    lines.push({
      rawLine:
        buffer.slice(
          start,
          index
        ),
      lineEnding: '\r\n'
    });

    index++;
    start =
      index + 1;
  } else {
    lines.push({
      rawLine:
        buffer.slice(
          start,
          index
        ),
      lineEnding: '\r'
    });

    start =
      index + 1;
  }
}


}

return {
lines,
remaining:
buffer.slice(start)
};
}

function splitLinesWithEndings(
text
) {
const result = [];

const regex =
/([^\r\n]*)(\r\n|\n|\r)?/g;

let match;

while (
(match = regex.exec(text)) !== null
) {
if (
match.index ===
regex.lastIndex
) {
regex.lastIndex++;
}


const rawLine =
  match[1] || '';

const lineEnding =
  match[2] || '';

if (
  rawLine === '' &&
  lineEnding === '' &&
  match.index === text.length
) {
  break;
}

result.push({
  rawLine,
  lineEnding
});


}

return result;
}

function dispatchProgress(
postMessage,
processedBytes,
totalBytes
) {
const percent =
totalBytes === 0
? 100
: Math.min(
100,
Math.floor(
(processedBytes /
totalBytes) *
100
)
);

dispatchMessage(
postMessage,
{
type: 'PROGRESS',
payload: {
processedBytes,
totalBytes,
percent
}
}
);
}

function formatMB(bytes) {
return (
Math.round(
bytes /
1024 /
1024
) +
' MB'
);
}
