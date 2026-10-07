import assert from 'node:assert/strict';

export function assertNoResidual(output, sensitiveValues = []) {
  if (typeof output !== 'string') {
    throw new TypeError('Sanitizer output must be a string');
  }

  for (const secret of sensitiveValues) {
    if (!secret || secret.length === 0) continue;

    assert.equal(
      output.includes(secret),
      false,
      `SECURITY INVARIANT VIOLATED: Raw sensitive value "${secret}" was present in output!`
    );
  }
}

export function assertNoResidualPatterns(output, residualPatterns = []) {
  if (typeof output !== 'string') {
    throw new TypeError('Sanitizer output must be a string');
  }

  for (const pattern of residualPatterns) {
    if (!(pattern instanceof RegExp)) {
      throw new TypeError(
        'Residual patterns must contain RegExp instances.'
      );
    }

    pattern.lastIndex = 0;

    assert.equal(
      pattern.test(output),
      false,
      `SECURITY INVARIANT VIOLATED: Residual sensitive pattern ${pattern} was present in output!`
    );

    pattern.lastIndex = 0;
  }
}

export async function assertFailClosedWorker(
  harness,
  harnessExecutionFn,
  expectedErrorPattern
) {
  if (!harness) {
    throw new TypeError(
      'assertFailClosedWorker requires a WorkerTestHarness instance.'
    );
  }

  await assert.rejects(
    async () => {
      await harnessExecutionFn();
    },
    expectedErrorPattern,
    'Execution failed to throw expected fail-closed error'
  );

  assert.equal(
    harness.status,
    'FAILED',
    'FAIL-CLOSED INVARIANT VIOLATED: Worker did not enter FAILED state.'
  );

  assert.equal(
    harness.getMessageTypes().includes('COMPLETE'),
    false,
    'FAIL-CLOSED INVARIANT VIOLATED: COMPLETE was emitted during failure.'
  );

  assert.equal(
    harness.getMessageTypes().includes('COMPLETE_BLOB'),
    false,
    'FAIL-CLOSED INVARIANT VIOLATED: COMPLETE_BLOB was emitted during failure.'
  );

  assert.equal(
    harness.getOutputText(),
    null,
    'FAIL-CLOSED INVARIANT VIOLATED: Output was exposed during failure.'
  );
}

export function assertProgressSequence(progressEvents) {
  assert.ok(
    Array.isArray(progressEvents),
    'Progress events must be an array.'
  );

  assert.ok(
    progressEvents.length > 0,
    'Expected at least one progress event.'
  );

  for (const event of progressEvents) {
    assert.equal(
      typeof event.processedBytes,
      'number',
      'processedBytes must be numeric.'
    );

    assert.equal(
      typeof event.totalBytes,
      'number',
      'totalBytes must be numeric.'
    );

    assert.equal(
      typeof event.percent,
      'number',
      'percent must be numeric.'
    );

    assert.ok(
      event.percent >= 0 && event.percent <= 100,
      `Invalid progress percentage: ${event.percent}`
    );
  }
}
