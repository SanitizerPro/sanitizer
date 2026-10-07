import test from 'node:test';
import assert from 'node:assert/strict';
import { ALL_RULES, PROFILES } from '../src/rules/index.js';
import { validateRules } from '../src/engine/rule-validator.js';

test('ALL_RULES passes validation', () => {
  assert.equal(validateRules(ALL_RULES), true);
});

test('ALL_RULES contains unique rule IDs', () => {
  const ids = ALL_RULES.map((rule) => rule.id);
  assert.equal(new Set(ids).size, ids.length, 'Rule IDs must be unique.');
});

test('all profiles contain valid rules', () => {
  for (const profile of Object.values(PROFILES)) {
    assert.equal(
      validateRules(profile.rules),
      true,
      `Profile '${profile.id}' contains invalid rules.`
    );
  }
});
