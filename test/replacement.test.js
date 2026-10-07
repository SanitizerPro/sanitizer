import test from 'node:test';
import assert from 'node:assert/strict';
import { TypeAwareTokenMap } from '../src/engine/token-map.js';
import { applyReplacement } from '../src/engine/replacement.js';

function applyRegexReplacement(rule, input, tokenMap, stats) {
  const regex = new RegExp(rule.regex.source, rule.regex.flags);

  return input.replace(regex, (...args) => {
    const match = args[0];
    const captureGroups = args.slice(1, args.length - 2).map((v) => v ?? '');
    return applyReplacement(rule, match, captureGroups, tokenMap, stats);
  });
}

test('whole-match replacement produces deterministic token', () => {
  const tokenMap = new TypeAwareTokenMap();
  const stats = { matches: {} };
  const rule = {
    id: 'test_secret',
    tokenType: 'SECRET',
    regex: /secret-[a-z0-9]+/i
  };

  const output = applyRegexReplacement(rule, 'value=secret-abc123', tokenMap, stats);
  assert.equal(output, 'value=[SL_SECRET_1]');
  assert.equal(stats.matches.test_secret, 1);
});

test('identical values reuse deterministic token', () => {
  const tokenMap = new TypeAwareTokenMap();
  const stats = { matches: {} };
  const rule = {
    id: 'test_secret',
    tokenType: 'SECRET',
    regex: /secret-[a-z0-9]+/gi
  };

  const output = applyRegexReplacement(rule, 'a=secret-abc b=secret-abc', tokenMap, stats);
  assert.equal(output, 'a=[SL_SECRET_1] b=[SL_SECRET_1]');
  assert.equal(stats.matches.test_secret, 2);
});

test('replacementGroup replaces only the selected capture', () => {
  const tokenMap = new TypeAwareTokenMap();
  const stats = { matches: {} };
  const rule = {
    id: 'test_password',
    tokenType: 'PASSWORD',
    regex: /(password\s*=\s*)([^\s]+)/i,
    replacementGroup: 2
  };

  const output = applyRegexReplacement(rule, 'password=SuperSecret123', tokenMap, stats);
  assert.equal(output, 'password=[SL_PASSWORD_1]');
  assert.equal(stats.matches.test_password, 1);
});
