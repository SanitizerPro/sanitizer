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

```
return;
```

}

if (data.type !== 'START') {
dispatchMessage(postMessage, {
type: 'ERROR',
error: "Unsupported worker message type '" + data.type + "'."
});

```
return;
```

}

currentAbortController = new AbortController();

const signal = currentAbortController.signal;

try {
const { content, rules, options = {} } = data.payload || {};

```
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
  const textInput = String(content ?? '');

  await processTextContent({
    textInput,
    rules,
    options,
    tokenMap,
    stats,
    signal,
    postMessage
  });
}
```

} catch (err) {
if (signal.aborted) {
dispatchMessage(postMessage, {
type: 'CANCELLED'
});
} else {
dispatchMessage(postMessage, {
type: 'ERROR',
error: err instanceof Error
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

```
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
```

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

try {
while (true) {
if (signal.aborted) {
throw new Error('Operation cancelled');
}

```
  const { value, done } = await reader.read();

  if (done) {
    break;
  }

  if (typeof value !== 'string') {
    throw new Error(
      'Streaming decoder returned invalid text data.'
    );
  }

  textBuffer += value;

  /*
   * TextDecoderStream returns decoded text. Re-encode the decoded
   * chunk to maintain UTF-8 byte-based progress accounting.
   */
  const encodedChunkBytes = new TextEncoder()
    .encode(value)
    .byteLength;

  processedBytes += encodedChunkBytes;

  const completeLines =
    extractCompleteLines(textBuffer);

  textBuffer = completeLines.remaining;

  for (const line of completeLines.lines) {
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
      stats,
      Boolean(options.strict)
    );

    activeBlockRule =
      result.activeBlockRule;

    activeBlockBuffer =
      result.activeBlockBuffer;

    activeBlockBytes =
      result.activeBlockBytes;

    if (result.output !== null) {
      outputChunks.push(result.output);
    }
  }

  dispatchProgress(
    postMessage,
    processedBytes,
    blob.size
  );
}

/*
 * Process a final line that has no terminating newline.
 */
if (textBuffer.length > 0) {
  const finalLine = {
    rawLine: textBuffer,
    lineEnding: ''
  };

  const result = processLine(
    finalLine.rawLine,
    finalLine.lineEnding,
    lineRules,
    blockRules,
    {
      activeBlockRule,
      activeBlockBuffer,
      activeBlockBytes
    },
    tokenMap,
    stats,
    Boolean(options.strict)
  );

  activeBlockRule =
    result.activeBlockRule;

  activeBlockBuffer =
    result.activeBlockBuffer;

  activeBlockBytes =
    result.activeBlockBytes;

  if (result.output !== null) {
    outputChunks.push(result.output);
  }
}

/*
 * A block that reaches EOF without its closing pattern is
 * rejected in strict mode. In non-strict mode the original
 * block is preserved.
 */
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
```

} finally {
try {
await reader.cancel();
} catch {
/*
* Reader cancellation is best-effort during cleanup.
*/
}
}
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
const totalBytes = new TextEncoder()
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

```
dispatchMessage(postMessage, {
  type: 'COMPLETE',
  payload: {
    sanitizedText: '',
    stats
  }
});

return;
```

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

```
return;
```

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
const lines = splitLinesWithEndings(textInput);

const outputLines = [];

let processedBytes = 0;

let activeBlockRule = null;
let activeBlockBuffer = '';
let activeBlockBytes = 0;

for (const line of lines) {
if (signal.aborted) {
throw new Error('Operation cancelled');
}

```
const lineByteCount = new TextEncoder()
  .encode(
    line.rawLine + line.lineEnding
  )
  .byteLength;

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
  stats,
  strict
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

processedBytes += lineByteCount;

dispatchProgress(
  postMessage,
  processedBytes,
  totalBytes
);
```

}

if (activeBlockRule) {
if (strict) {
throw new Error(
"Unterminated block detected for rule '" +
activeBlockRule.id +
"' at EOF."
);
}

```
outputLines.push(activeBlockBuffer);
```

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
stats,
strict
) {
let {
activeBlockRule,
activeBlockBuffer,
activeBlockBytes
} = blockState;

const lineByteCount = new TextEncoder()
.encode(
rawLine + lineEnding
)
.byteLength;

/*

* Continue an existing block.
  */
  if (activeBlockRule) {
  const maxAllowedBytes =
  activeBlockRule.maxBytes ??
  DEFAULT_MAX_BLOCK_BYTES;

```
activeBlockBytes += lineByteCount;
```

```
if (activeBlockBytes > maxAllowedBytes) {
  throw new Error(
    "Rule '" +
    activeBlockRule.id +
    "' exceeded maxBytes limit of " +
    maxAllowedBytes +
    ' bytes.'
  );
}

activeBlockBuffer +=
  rawLine + lineEnding;

if (
  testRegex(
    activeBlockRule.endRegex,
    rawLine
  )
) {
  const redactedBlock =
    applyBlockReplacement(
      activeBlockRule,
      activeBlockBuffer,
      tokenMap,
      stats
    );

  return {
    output: redactedBlock,
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
```

}

/*

* Look for a new block.
  */
  for (const blockRule of blockRules) {
  if (
  !testRegex(
  blockRule.startRegex,
  rawLine
  )
  ) {
  continue;
  }

```
activeBlockRule = blockRule;
```

```
activeBlockBuffer =
  rawLine + lineEnding;

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

/*
 * Support a block whose start and end occur
 * on the same line.
 */
if (
  testRegex(
    blockRule.endRegex,
    rawLine
  )
) {
  const redactedBlock =
    applyBlockReplacement(
      blockRule,
      activeBlockBuffer,
      tokenMap,
      stats
    );

  return {
    output: redactedBlock,
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
```

}

/*

* Normal line processing.
  */
  let currentLine = rawLine;

for (const rule of lineRules) {
currentLine = executeLineRule(
rule,
currentLine,
tokenMap,
stats
);
}

return {
output:
currentLine + lineEnding,
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
/*

* Clone the RegExp so a global/sticky rule cannot
* leak lastIndex state between lines.
  */
  const regex = new RegExp(
  rule.regex.source,
  rule.regex.flags
  );

return text.replace(
regex,
(...args) => {
const match = args[0];

```
  /*
   * String.replace callback arguments are:
   *
   * match
   * capture groups...
   * offset
   * complete string
   * groups
   *
   * The final two values are excluded here.
   */
  const captureGroups = args
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
```

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
/*

* Always clone the rule RegExp because rules may
* contain global or sticky flags.
  */
  const safeRegex = new RegExp(
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
let i = 0;
i < buffer.length;
i++
) {
const char = buffer[i];

```
/*
 * LF
 */
if (char === '\n') {
  lines.push({
    rawLine:
      buffer.slice(start, i),
    lineEnding: '\n'
  });

  start = i + 1;

  continue;
}

/*
 * CR or CRLF
 */
if (char === '\r') {
  if (
    i + 1 < buffer.length &&
    buffer[i + 1] === '\n'
  ) {
    lines.push({
      rawLine:
        buffer.slice(start, i),
      lineEnding: '\r\n'
    });

    i++;
    start = i + 1;
  } else {
    lines.push({
      rawLine:
        buffer.slice(start, i),
      lineEnding: '\r'
    });

    start = i + 1;
  }
}
```

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
match.index === regex.lastIndex
) {
regex.lastIndex++;
}

```
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
```

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

dispatchMessage(postMessage, {
type: 'PROGRESS',
payload: {
processedBytes,
totalBytes,
percent
}
});
}

function formatMB(bytes) {
return (
Math.round(
bytes / 1024 / 1024
) +
' MB'
);
}
