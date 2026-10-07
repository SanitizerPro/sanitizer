import { COMMON_RULES } from './common.rules.js';

export const ALL_RULES = [
  ...COMMON_RULES
];

export const PROFILES = {
  DEFAULT_SECURITY: {
    id: 'DEFAULT_SECURITY',
    name: 'Default Security Baseline',
    description: 'Standard security detection profile',
    rules: ALL_RULES
  }
};
