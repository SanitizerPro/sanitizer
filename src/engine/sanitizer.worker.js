import { TypeAwareTokenMap } from './token-map.js';
import { applyReplacement } from './replacement.js';
import { validateRules } from './rule-validator.js';

const DEFAULT_MAX_BLOCK_BYTES = 1048576; // 1 MB default

let currentAbortController = null;

self.onmessage = async (event) => {
  const { data, postMessage } = parseWorkerEvent(event);

  if (!data || !data.type) return;

  if (data.type === 'CANCEL') {
    if (currentAbortController) {
      currentAbortController.abort();
    }
    return;
  }

  if (data.type === 'START') {
    currentAbortController = new AbortController();
    const signal = currentAbortController.signal;

    try {
      const { content, rules, options = {} } = data.payload || {};
      validateRules(rules);

      const tokenMap = new TypeAwareTokenMap(options.tokenMapState);
      const stats = { matches: {} };

      const isBlobInput = typeof Blob !== 'undefined' && content instanceof Blob;
      const textInput = isBlobInput ? await content.text() : String(content ?? '');
      const totalBytes = new TextEncoder().encode(textInput).byteLength;

      if (totalBytes === 0) {
        dispatchMessage(postMessage, {
          type: 'PROGRESS',
          payload: { processedBytes: 0, totalBytes: 0, percent: 100 }
        });

        if (isBlobInput) {
          dispatchMessage(postMessage, {
            type: 'COMPLETE_BLOB',
            payload: { blob: new Blob([''], { type: content.type || 'text/plain' }), stats }
          });
        } else {
          dispatchMessage(postMessage, {
            type: 'COMPLETE',
            payload: { sanitizedText: '', stats }
          });
        }
        return;
      }

      const lineRules = rules.filter((r) => r.scope !== 'block');
      const blockRules = rules.filter((r) => r.scope === 'block');

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
        dispatchMessage(postMessage, { type: 'CANCELLED' });
        return;
      }

      if (isBlobInput) {
        const outputBlob = new Blob([sanitizedText], { type: content.type || 'text/plain' });
        dispatchMessage(postMessage, {
          type: 'COMPLETE_BLOB',
          payload: { blob: outputBlob, stats }
        });
      } else {
        dispatchMessage(postMessage, {
          type: 'COMPLETE',
          payload: { sanitizedText, stats }
        });
      }
    } catch (err) {
      if (signal.aborted) {
        dispatchMessage(postMessage, { type: 'CANCELLED' });
      } else {
        dispatchMessage(postMessage, {
          type: 'ERROR',
          error: err instanceof Error ? err.message : String(err)
        });
      }
    } finally {
      currentAbortController = null;
    }
  }
};

function parseWorkerEvent(event) {
  const data = event.data || event;
  const postMessage = event.postMessage 
    ? event.postMessage 
    : (msg) => self.postMessage(msg);
  return { data, postMessage };
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
  const lines = splitLinesWithEndings(textInput);
  const outputLines = [];
  let processedBytes = 0;

  let activeBlockRule = null;
  let activeBlockBuffer = '';
  let activeBlockBytes = 0;

  for (let i = 0; i < lines.length; i++) {
    if (signal.aborted) {
      throw new Error('Operation cancelled');
    }

    const { rawLine, lineEnding } = lines[i];
    const lineByteCount = new TextEncoder().encode(rawLine + lineEnding).byteLength;

    if (activeBlockRule) {
      const maxAllowedBytes = activeBlockRule.maxBytes ?? DEFAULT_MAX_BLOCK_BYTES;
      activeBlockBytes += lineByteCount;

      if (activeBlockBytes > maxAllowedBytes) {
        throw new Error(
          `Rule '${activeBlockRule.id}' exceeded maxBytes limit of ${maxAllowedBytes} bytes.`
        );
      }

      activeBlockBuffer += rawLine + lineEnding;

      if (activeBlockRule.endRegex.test(rawLine)) {
        const redactedBlock = applyBlockReplacement(
          activeBlockRule,
          activeBlockBuffer,
          tokenMap,
          stats
        );
        outputLines.push(redactedBlock);

        activeBlockRule = null;
        activeBlockBuffer = '';
        activeBlockBytes = 0;
      }
    } else {
      let startedBlock = false;
      for (const blockRule of blockRules) {
        if (blockRule.startRegex.test(rawLine)) {
          activeBlockRule = blockRule;
          activeBlockBuffer = rawLine + lineEnding;
          activeBlockBytes = lineByteCount;
          const maxAllowedBytes = blockRule.maxBytes ?? DEFAULT_MAX_BLOCK_BYTES;

          if (activeBlockBytes > maxAllowedBytes) {
            throw new Error(
              `Rule '${blockRule.id}' exceeded maxBytes limit of ${maxAllowedBytes} bytes.`
            );
          }

          if (blockRule.endRegex.test(rawLine)) {
            const redactedBlock = applyBlockReplacement(
              blockRule,
              activeBlockBuffer,
              tokenMap,
              stats
            );
            outputLines.push(redactedBlock);

            activeBlockRule = null;
            activeBlockBuffer = '';
            activeBlockBytes = 0;
          }

          startedBlock = true;
          break;
        }
      }

      if (!startedBlock) {
        let currentLine = rawLine;
        for (const rule of lineRules) {
          currentLine = executeLineRule(rule, currentLine, tokenMap, stats);
        }
        outputLines.push(currentLine + lineEnding);
      }
    }

    processedBytes += lineByteCount;
    const percent = Math.min(100, Math.floor((processedBytes / totalBytes) * 100));

    dispatchMessage(postMessage, {
      type: 'PROGRESS',
      payload: { processedBytes, totalBytes, percent }
    });
  }

  if (activeBlockRule) {
    if (strict) {
      throw new Error(`Unterminated block detected for rule '${activeBlockRule.id}' at EOF.`);
    } else {
      outputLines.push(activeBlockBuffer);
    }
  }

  return outputLines.join('');
}

function executeLineRule(rule, text, tokenMap, stats) {
  const regex = new RegExp(rule.regex.source, rule.regex.flags);
  return text.replace(regex, (...args) => {
    const match = args[0];
    const captureGroups = args.slice(1, args.length - 2).map((g) => (g === undefined ? '' : g));
    return applyReplacement(rule, match, captureGroups, tokenMap, stats);
  });
}

function applyBlockReplacement(rule, blockBuffer, tokenMap, stats) {
  return applyReplacement(rule, blockBuffer, [], tokenMap, stats);
}

function splitLinesWithEndings(text) {
  const result = [];
  const regex = /([^\r\n]*)(\r\n|\n|\r)?/g;
  let match;

  while ((match = regex.exec(text)) !== null) {
    if (match.index === regex.lastIndex) {
      regex.lastIndex++;
    }

    const rawLine = match[1] || '';
    const lineEnding = match[2] || '';

    if (rawLine === '' && lineEnding === '' && match.index === text.length) {
      break;
    }

    result.push({ rawLine, lineEnding });
  }

  return result;
}
