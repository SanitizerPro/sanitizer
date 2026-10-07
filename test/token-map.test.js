import test from 'node:test';
import assert from 'node:assert/strict';
import { TypeAwareTokenMap } from '../src/engine/token-map.js';

test('generates deterministic tokens with 1-based indexing per token type', () => {
  const tokenMap = new TypeAwareTokenMap();
  assert.equal(tokenMap.getOrSet('secret1', 'PASSWORD'), '[SL_PASSWORD_1]');
  assert.equal(tokenMap.getOrSet('secret2', 'PASSWORD'), '[SL_PASSWORD_2]');
});

test('returns identical token for identical value and type', () => {
  const tokenMap = new TypeAwareTokenMap();
  assert.equal(tokenMap.getOrSet('my-key', 'API_KEY'), '[SL_API_KEY_1]');
  assert.equal(tokenMap.getOrSet('my-key', 'API_KEY'), '[SL_API_KEY_1]');
});

test('generates distinct tokens when same value is mapped to different token types', () => {
  const tokenMap = new TypeAwareTokenMap();
  assert.equal(tokenMap.getOrSet('shared-secret', 'PASSWORD'), '[SL_PASSWORD_1]');
  assert.equal(tokenMap.getOrSet('shared-secret', 'API_KEY'), '[SL_API_KEY_1]');
});

test('maintains independent counter sequences per token type', () => {
  const tokenMap = new TypeAwareTokenMap();
  assert.equal(tokenMap.getOrSet('p1', 'PASSWORD'), '[SL_PASSWORD_1]');
  assert.equal(tokenMap.getOrSet('k1', 'KEY'), '[SL_KEY_1]');
  assert.equal(tokenMap.getOrSet('p2', 'PASSWORD'), '[SL_PASSWORD_2]');
  assert.equal(tokenMap.getOrSet('k2', 'KEY'), '[SL_KEY_2]');
});
