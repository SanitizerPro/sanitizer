import test from 'node:test';
import assert from 'node:assert/strict';
import { validateRules } from '../src/engine/rule-validator.js';

function validLineRule(overrides = {}) {
  return {
    id: 'test_rule',
    description: 'Test rule',
    scope: 'line',
    regex: /secret/,
    tokenType: 'SECRET',
    ...overrides
  };
}

function validBlockRule(overrides = {}) {
  return {
    id: 'test_block',
    description: 'Test block rule',
    scope: 'block',
    startRegex: /BEGIN/,
    endRegex: /END/,
    tokenType: 'PRIVATE_KEY',
    ...overrides
  };
}

test('valid line rules pass validation', () => {
  assert.equal(validateRules([validLineRule()]), true);
});

test('valid block rules pass validation', () => {
  assert.equal(validateRules([validBlockRule()]), true);
});

test('missing rule ID is rejected', () => {
  assert.throws(
    () => validateRules([validLineRule({ id: undefined })]),
    /Rule missing required string 'id'/
  );
});

test('duplicate rule IDs are rejected', () => {
  assert.throws(
    () => validateRules([validLineRule({ id: 'dup' }), validLineRule({ id: 'dup' })]),
    /Duplicate rule ID detected/
  );
});

test('maxBytes zero is rejected', () => {
  assert.throws(
    () => validateRules([validBlockRule({ maxBytes: 0 })]),
    /has invalid maxBytes/
  );
});
