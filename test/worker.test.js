import test from 'node:test';
import assert from 'node:assert/strict';

if (!globalThis.self) {
  globalThis.self = globalThis;
}

const workerModule = await import('../src/engine/sanitizer.worker.js');
import { WorkerTestHarness } from './helpers/worker-harness.js';
import {
  assertNoResidual,
  assertFailClosedWorker,
  assertProgressSequence
} from './helpers/assertions.js';

const sampleLineRule = {
  id: 'test_token',
  description: 'Test token rule',
  scope: 'line',
  regex: /tok-[a-z0-9]{8}/i,
  tokenType: 'TOKEN'
};

const sampleBlockRule = {
  id: 'test_pem',
  description: 'Test PEM block rule',
  scope: 'block',
  startRegex: /-----BEGIN PRIVATE KEY-----/,
  endRegex: /-----END PRIVATE KEY-----/,
  maxBytes: 1024,
  tokenType: 'PRIVATE_KEY'
};

test('string input completes with COMPLETE payload and updated stats', async () => {
  const harness = new WorkerTestHarness(workerModule);
  const input = 'Header line\ntok-abc12345\nFooter line';

  const { output, stats } = await harness.run(input, [sampleLineRule]);

  assert.equal(harness.status, 'COMPLETED');
  assert.equal(output, 'Header line\n[SL_TOKEN_1]\nFooter line');
  assert.equal(stats.matches.test_token, 1);
  assertNoResidual(output, ['tok-abc12345']);
  assertProgressSequence(harness.getProgressEvents());
});

test('Blob input completes with COMPLETE_BLOB payload', async () => {
  const harness = new WorkerTestHarness(workerModule);
  const rawText = 'secret_data: tok-xyz98765';
  const blobInput = new Blob([rawText], { type: 'text/plain' });

  const { output, stats } = await harness.run(blobInput, [sampleLineRule]);

  assert.equal(harness.status, 'COMPLETED');
  assert.equal(output, 'secret_data: [SL_TOKEN_1]');
  assert.equal(stats.matches.test_token, 1);
  assertNoResidual(output, ['tok-xyz98765']);
});

test('same-line block exceeding maxBytes fails closed immediately', async () => {
  const harness = new WorkerTestHarness(workerModule);
  const smallLimitBlockRule = { ...sampleBlockRule, maxBytes: 50 };
  const oversizedLine = '-----BEGIN PRIVATE KEY-----' + 'A'.repeat(100) + '-----END PRIVATE KEY-----';

  await assertFailClosedWorker(
    harness,
    () => harness.run(oversizedLine, [smallLimitBlockRule]),
    /exceeded maxBytes limit/
  );
});

test('cancellation during Blob acquisition transitions worker to CANCELLED', async () => {
  const harness = new WorkerTestHarness(workerModule);
  const largeBlob = new Blob(
    [Array(1000).fill('line with tok-12345678').join('\n')],
    { type: 'text/plain' }
  );

  const runPromise = harness.run(largeBlob, [sampleLineRule]);
  harness.cancel();

  await assert.rejects(() => runPromise, /Operation cancelled/);
  assert.equal(harness.status, 'CANCELLED');
  assert.equal(harness.getOutputText(), null);
});
