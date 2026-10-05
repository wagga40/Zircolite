import { flushSync } from 'svelte';
import { describe, expect, it } from 'vitest';
import { Superseded } from '../src/engine/queries';
import { run, runAgain } from '../src/state/run.svelte';
import { failedSlot, Panel } from '../src/ui/panel.svelte';

const later = <T,>() => {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((a, b) => { resolve = a; reject = b; });
  return { promise, resolve, reject };
};
const settle = () => new Promise((resolve) => setTimeout(resolve, 0));

describe('a panel', () => {
  it('starts pending, or idle when asked', () => {
    expect(new Panel<number>().slot).toEqual({ data: null, pending: true, failure: null, stopped: false });
    expect(new Panel<number>(false).slot.pending).toBe(false);
  });

  it('keeps only the answer to its latest request', async () => {
    const panel = new Panel<string>();
    const first = later<string>();
    const second = later<string>();
    panel.load(() => first.promise);
    panel.load(() => second.promise);
    second.resolve('new');
    first.resolve('old');
    await settle();
    flushSync();
    expect(panel.slot).toEqual({ data: 'new', pending: false, failure: null, stopped: false });
  });

  it('keeps the earlier answer on screen while pending, then drops it on failure', async () => {
    const panel = new Panel<string>();
    panel.load(() => Promise.resolve('a'));
    await settle();
    const next = later<string>();
    panel.load(() => next.promise);
    expect(panel.slot).toEqual({ data: 'a', pending: true, failure: null, stopped: false });
    next.reject(new Error('Binder Error: no such column'));
    await settle();
    expect(panel.slot).toEqual({ data: null, pending: false, failure: 'Binder Error: no such column', stopped: false });
  });

  it('a fetch that throws at once is a failure, not an exception', async () => {
    const panel = new Panel<string>();
    panel.load(() => {
      throw new Error('boom');
    });
    await settle();
    expect(panel.slot.failure).toBe('boom');
  });
});

describe('a stale request', () => {
  it('is ignored when it fails after a newer one was made', async () => {
    const panel = new Panel<string>();
    const first = later<string>();
    const second = later<string>();
    panel.load(() => first.promise);
    panel.load(() => second.promise);
    second.resolve('new');
    await settle();
    first.reject(new Error('late'));
    await settle();
    expect(panel.slot).toEqual({ data: 'new', pending: false, failure: null, stopped: false });
  });
});

describe('a failed slot', () => {
  it('says stopped after a Stop, interrupted otherwise', () => {
    run.stopped = true;
    expect(failedSlot(new Superseded())).toEqual({ data: null, pending: false, failure: null, stopped: true });
    runAgain();
    expect(failedSlot(new Superseded())).toEqual({ data: null, pending: false, failure: 'the query was interrupted', stopped: false });
  });
});
