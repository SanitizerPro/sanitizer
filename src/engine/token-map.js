export class TypeAwareTokenMap {
  constructor(initialState = {}) {
    this.tokenCounts = new Map();
    this.valueToToken = new Map();

    if (initialState.tokenCounts) {
      for (const [k, v] of Object.entries(initialState.tokenCounts)) {
        this.tokenCounts.set(k, v);
      }
    }
    if (initialState.valueToToken) {
      for (const [k, v] of Object.entries(initialState.valueToToken)) {
        this.valueToToken.set(k, v);
      }
    }
  }

  getOrSet(value, tokenType = 'GENERIC') {
    const key = `${tokenType}:${value}`;
    if (this.valueToToken.has(key)) {
      return this.valueToToken.get(key);
    }

    const currentCount = (this.tokenCounts.get(tokenType) || 0) + 1;
    this.tokenCounts.set(tokenType, currentCount);

    const token = `[SL_${tokenType.toUpperCase()}_${currentCount}]`;
    this.valueToToken.set(key, token);
    return token;
  }

  toJSON() {
    return {
      tokenCounts: Object.fromEntries(this.tokenCounts),
      valueToToken: Object.fromEntries(this.valueToToken)
    };
  }
}
