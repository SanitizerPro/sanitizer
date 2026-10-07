import { EventEmitter } from 'node:events';

export class WorkerTestHarness extends EventEmitter {
  constructor(workerModule) {
    super();

    if (!workerModule || typeof workerModule.onmessage !== 'function') {
      throw new TypeError('Worker module must expose an onmessage function.');
    }

    this.worker = workerModule;
    this.messages = [];
    this.output = null;
    this.stats = null;
    this.error = null;
    this.status = 'IDLE';
    this.progressEvents = [];
  }

  postMessage = (message) => {
    this.messages.push(message);

    switch (message.type) {
      case 'PROGRESS': {
        this.progressEvents.push(message.payload);
        this.emit('progress', message.payload);
        break;
      }

      case 'COMPLETE': {
        this.output = message.payload.sanitizedText;
        this.stats = message.payload.stats;
        this.status = 'COMPLETED';
        this.emit('complete', {
          output: this.output,
          stats: this.stats
        });
        break;
      }

      case 'COMPLETE_BLOB': {
        this.stats = message.payload.stats;
        this.status = 'COMPLETED';

        Promise.resolve(message.payload.blob.text()).then((text) => {
          this.output = text;

          this.emit('complete', {
            output: this.output,
            stats: this.stats
          });
        });

        break;
      }

      case 'ERROR': {
        this.error = new Error(message.error);
        this.status = 'FAILED';
        this.emit('error', this.error);
        break;
      }

      case 'CANCELLED': {
        this.status = 'CANCELLED';
        this.emit('cancelled');
        break;
      }

      default:
        throw new Error(`Unexpected worker message type '${message.type}'.`);
    }
  };

  async run(content, rules, options = {}) {
    this.reset();

    return new Promise((resolve, reject) => {
      const onComplete = ({ output, stats }) => {
        cleanup();
        resolve({ output, stats });
      };

      const onError = (error) => {
        cleanup();
        reject(error);
      };

      const onCancelled = () => {
        cleanup();
        reject(new Error('Operation cancelled'));
      };

      const cleanup = () => {
        this.removeListener('complete', onComplete);
        this.removeListener('error', onError);
        this.removeListener('cancelled', onCancelled);
      };

      this.once('complete', onComplete);
      this.once('error', onError);
      this.once('cancelled', onCancelled);

      try {
        this.worker.onmessage({
          data: {
            type: 'START',
            payload: {
              content,
              rules,
              options
            }
          },
          postMessage: this.postMessage
        });
      } catch (error) {
        cleanup();
        reject(error);
      }
    });
  }

  cancel() {
    this.worker.onmessage({
      data: {
        type: 'CANCEL'
      },
      postMessage: this.postMessage
    });
  }

  waitForProgress() {
    if (this.progressEvents.length > 0) {
      return Promise.resolve(
        this.progressEvents[this.progressEvents.length - 1]
      );
    }

    return new Promise((resolve) => {
      this.once('progress', resolve);
    });
  }

  getOutputText() {
    return this.output;
  }

  getStats() {
    return this.stats;
  }

  getProgressEvents() {
    return [...this.progressEvents];
  }

  getMessageTypes() {
    return this.messages.map((message) => message.type);
  }

  reset() {
    this.messages = [];
    this.output = null;
    this.stats = null;
    this.error = null;
    this.status = 'PROCESSING';
    this.progressEvents = [];
  }
}
