export const COMMON_RULES = [
  {
    id: 'common-jwt',
    description: 'JSON Web Token (JWT)',
    scope: 'line',
    regex: /bearer\s+(eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_.-]+)/gi,
    replacementGroup: 1,
    tokenType: 'JWT'
  },
  {
    id: 'common-password-assignment',
    description: 'Generic key-value password pattern',
    scope: 'line',
    regex: /(password\s*[:=]\s*)([^\s"',;]+)/gi,
    replacementGroup: 2,
    tokenType: 'PASSWORD'
  }
];
