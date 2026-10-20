import { afterEach, describe, expect, it, vi } from 'vitest';
import { holdStop, run, runAgain, stopAll } from '../src/state/run.svelte';

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

  it('counts the Stop buttons views show of their own, each until its view lets go', () => {
    const table = holdStop();
    const console = holdStop();
    expect(run.ownStops).toBe(2);
    table();
    table();
    expect(run.ownStops).toBe(1);
    console();
    expect(run.ownStops).toBe(0);
  });

  it('runAgain clears the stop and moves the generation on', () => {
    stopAll({ cancel: () => {} });
    const before = run.generation;
    runAgain();
    expect(run.stopped).toBe(false);
    expect(run.generation).toBe(before + 1);
  });
});
