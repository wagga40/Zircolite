import { afterEach, describe, expect, it, vi } from 'vitest';
import { run, runAgain, stopAll } from '../src/state/run.svelte';

describe('run state', () => {
  afterEach(() => {
    run.stopped = false;
    run.generation = 0;
  });

  it('stopAll marks the page stopped and cancels every lane', () => {
    const cancel = vi.fn();
    stopAll({ cancel });
    expect(run.stopped).toBe(true);
    expect(cancel).toHaveBeenCalledWith();
  });

  it('runAgain clears the stop and moves the generation on', () => {
    stopAll({ cancel: () => {} });
    const before = run.generation;
    runAgain();
    expect(run.stopped).toBe(false);
    expect(run.generation).toBe(before + 1);
  });
});
