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
return;
}

currentAbortController = new AbortController();

const signal = currentAbortController.signal;

try {
const {
content,
rules,
options = {}
} = data.payload || {};

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

const textInput = isBlobInput
  ? await content.text()
  : String(content ?? '');

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

  if (isBlobInput) {
    dispatchMessage(postMessage, {
      type: 'COMPLETE_BLOB',
      payload: {
        blob: new Blob(
          [''],
          {
            type:
              content.type ||
              'text/plain'
          }
        ),
        stats
      }
    });
  } else {
    dispatchMessage(postMessage, {
      type: 'COMPLETE',
      payload: {
        sanitizedText: '',
        stats
      }
    });
  }

  return;
}

const lineRules = rules.filter(
  (rule) => rule.scope !== 'block'
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

if (isBlobInput) {
  const outputBlob = new Blob(
    [sanitizedText],
    {
      type:
        content.type ||
        'text/plain'
    }
  );

  dispatchMessage(postMessage, {
    type: 'COMPLETE_BLOB',
    payload: {
      blob: outputBlob,
      stats
    }
  });
} else {
  dispatchMessage(postMessage, {
    type: 'COMPLETE',
    payload: {
      sanitizedText,
      stats
    }
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
const lines = splitLinesWithEndings(
textInput
);

const outputLines = [];

let processedBytes = 0;

let activeBlockRule = null;
let activeBlockBuffer = '';
let activeBlockBytes = 0;

for (let i = 0; i < lines.length; i++) {
if (signal.aborted) {
throw new Error(
'Operation cancelled'
);
}

```
const {
  rawLine,
  lineEnding
} = lines[i];

const lineByteCount =
  new TextEncoder()
    .encode(
      rawLine + lineEnding
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
      `Rule '${activeBlockRule.id}' exceeded maxBytes limit of ${maxAllowedBytes} bytes.`
    );
  }

  activeBlockBuffer +=
    rawLine + lineEnding;

  if (
    activeBlockRule.endRegex.test(
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

    outputLines.push(
      redactedBlock
    );

    activeBlockRule = null;
    activeBlockBuffer = '';
    activeBlockBytes = 0;
  }
} else {
  let startedBlock = false;

  for (
    const blockRule of blockRules
  ) {
    if (
      blockRule.startRegex.test(
        rawLine
      )
    ) {
      activeBlockRule =
        blockRule;

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
          `Rule '${blockRule.id}' exceeded maxBytes limit of ${maxAllowedBytes} bytes.`
        );
      }

      if (
        blockRule.endRegex.test(
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

        outputLines.push(
          redactedBlock
        );

        activeBlockRule = null;
        activeBlockBuffer = '';
        activeBlockBytes = 0;
      }

      startedBlock = true;
      break;
    }
  }

  if (!startedBlock) {
    let currentLine =
      rawLine;

    for (
      const rule of lineRules
    ) {
      currentLine =
        executeLineRule(
          rule,
          currentLine,
          tokenMap,
          stats
        );
    }

    outputLines.push(
      currentLine + lineEnding
    );
  }
}

processedBytes +=
  lineByteCount;

const percent =
  Math.min(
    100,
    Math.floor(
      (
        processedBytes /
        totalBytes
      ) * 100
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
```

}

if (activeBlockRule) {
if (strict) {
throw new Error(
`Unterminated block detected for rule '${activeBlockRule.id}' at EOF.`
);
}

```
outputLines.push(
  activeBlockBuffer
);
```

}

return outputLines.join('');
}

function executeLineRule(
rule,
text,
tokenMap,
stats
) {
const regex = new RegExp(
rule.regex.source,
rule.regex.flags
);

return text.replace(
regex,
(...args) => {
const match = args[0];

```
  const captureGroups =
    args
      .slice(
        1,
        args.length - 2
      )
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

function applyReplacement(
rule,
match,
captureGroups,
tokenMap,
stats
) {
if (
!rule ||
typeof rule !== 'object'
) {
throw new TypeError(
'Invalid rule object passed to applyReplacement'
);
}

const tokenType =
rule.tokenType ||
'GENERIC';

const ruleId =
rule.id ||
'unknown';

if (
stats &&
stats.matches
) {
stats.matches[ruleId] =
(
stats.matches[ruleId] ||
0
) + 1;
}

if (
rule.replacementGroup ===
undefined ||
rule.replacementGroup ===
null
) {
return tokenMap.getOrSet(
match,
tokenType
);
}

const groupIdx =
Number(
rule.replacementGroup
);

if (
!Number.isInteger(
groupIdx
) ||
groupIdx < 1
) {
return match;
}

const targetValue =
captureGroups[
groupIdx - 1
];

if (
targetValue ===
undefined ||
targetValue === null ||
targetValue === ''
) {
return match;
}

const token =
tokenMap.getOrSet(
targetValue,
tokenType
);

const targetIndex =
match.indexOf(
targetValue
);

if (targetIndex !== -1) {
return (
match.slice(
0,
targetIndex
) +
token +
match.slice(
targetIndex +
targetValue.length
)
);
}

return match;
}

function validateRules(rules) {
if (
!Array.isArray(rules) ||
rules.length === 0
) {
throw new Error(
'Rules payload must be a non-empty array.'
);
}

const seenIds = new Set();

for (
const rule of rules
) {
if (
!rule ||
typeof rule !== 'object'
) {
throw new Error(
'Rule item must be a valid object.'
);
}

```
if (
  typeof rule.id !== 'string' ||
  rule.id.trim() === ''
) {
  throw new Error(
    "Rule missing required string 'id'."
  );
}

if (
  seenIds.has(rule.id)
) {
  throw new Error(
    `Duplicate rule ID detected: '${rule.id}'. Rule IDs must be unique.`
  );
}

seenIds.add(rule.id);

if (
  typeof rule.tokenType !==
    'string' ||
  rule.tokenType.trim() === ''
) {
  throw new Error(
    `Rule '${rule.id}' missing required string 'tokenType'.`
  );
}

const scope =
  rule.scope ?? 'line';

if (
  scope !== 'line' &&
  scope !== 'block'
) {
  throw new Error(
    `Rule '${rule.id}' has invalid scope '${scope}'. Must be 'line' or 'block'.`
  );
}

if (scope === 'line') {
  if (
    !(
      rule.regex instanceof
      RegExp
    )
  ) {
    throw new Error(
      `Line rule '${rule.id}' must provide a valid RegExp instance.`
    );
  }
} else {
  if (
    !(
      rule.startRegex instanceof
      RegExp
    ) ||
    !(
      rule.endRegex instanceof
      RegExp
    )
  ) {
    throw new Error(
      `Block rule '${rule.id}' requires valid 'startRegex' and 'endRegex' RegExp instances.`
    );
  }
}

if (
  rule.replacementGroup !==
  undefined
) {
  const rg =
    rule.replacementGroup;

  if (
    !Number.isInteger(rg) ||
    rg < 1
  ) {
    throw new Error(
      `Rule '${rule.id}' has invalid replacementGroup '${rg}'. Must be a positive integer.`
    );
  }
}

if (
  rule.maxBytes !==
  undefined
) {
  const mb =
    rule.maxBytes;

  if (
    !Number.isInteger(mb) ||
    mb <= 0 ||
    !Number.isSafeInteger(mb)
  ) {
    throw new Error(
      `Rule '${rule.id}' has invalid maxBytes '${mb}'. It must be a positive safe integer.`
    );
  }
}

if (
  rule.priority !==
  undefined
) {
  const p =
    rule.priority;

  if (
    typeof p !== 'number' ||
    !Number.isInteger(p) ||
    !Number.isFinite(p)
  ) {
    throw new Error(
      `Rule '${rule.id}' has invalid priority '${p}'. Priority must be an integer.`
    );
  }
}
```

}

return true;
}

class TypeAwareTokenMap {
constructor(initialState = {}) {
this.tokenCounts = new Map();
this.valueToToken = new Map();

```
if (
  initialState.tokenCounts
) {
  for (
    const [key, value] of
      Object.entries(
        initialState.tokenCounts
      )
  ) {
    this.tokenCounts.set(
      key,
      value
    );
  }
}

if (
  initialState.valueToToken
) {
  for (
    const [key, value] of
      Object.entries(
        initialState.valueToToken
      )
  ) {
    this.valueToToken.set(
      key,
      value
    );
  }
}
```

}

getOrSet(
value,
tokenType = 'GENERIC'
) {
const key =
`${tokenType}:${value}`;

```
if (
  this.valueToToken.has(key)
) {
  return this.valueToToken.get(
    key
  );
}

const currentCount =
  (
    this.tokenCounts.get(
      tokenType
    ) || 0
  ) + 1;

this.tokenCounts.set(
  tokenType,
  currentCount
);

const token =
  `[SL_${tokenType.toUpperCase()}_${currentCount}]`;

this.valueToToken.set(
  key,
  token
);

return token;
```

}

toJSON() {
return {
tokenCounts:
Object.fromEntries(
this.tokenCounts
),

```
  valueToToken:
    Object.fromEntries(
      this.valueToToken
    )
};
```

}
}
