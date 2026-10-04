import { flushSync } from 'svelte';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { EMPTY, encode } from '../src/state/hash';
import { bindHash, View } from '../src/state/view.svelte';
import { DETECTIONS_PREDICATE } from '../src/state/where';

describe('View.apply', () => {
  it('keeps the same array when an equal one is applied', () => {
    const view = new View();
    view.apply({ ...EMPTY, cols: ['A'] });
    const kept = view.cols;
    view.apply({ ...EMPTY, cols: ['A'] });
    expect(view.cols).toBe(kept);
    view.apply({ ...EMPTY, cols: ['B'] });
    expect(view.cols).toEqual(['B']);
  });

  it('keeps the same range when an equal one is applied', () => {
    const view = new View();
    view.apply({ ...EMPTY, t: [1, 2] });
    const kept = view.t;
    view.apply({ ...EMPTY, t: [1, 2] });
    expect(view.t).toBe(kept);
  });

  it('round-trips through snapshot', () => {
    const view = new View();
    const next = { route: 'timeline' as const, q: 'x', t: [1, 2] as [number, number], d: true, cols: ['A'], uid: 7, desc: true };
    view.apply(next);
    expect(view.snapshot()).toEqual(next);
  });
});

describe('bindHash', () => {
  const listeners = new Map<string, () => void>();
  const location = { hash: '', replace: vi.fn((h: string) => { location.hash = h; }) };
  const window = {
    addEventListener: vi.fn((name: string, fn: () => void) => { listeners.set(name, fn); }),
    removeEventListener: vi.fn((name: string) => { listeners.delete(name); }),
  };

  function setup(hash: string) {
    location.hash = hash;
    location.replace.mockClear();
    listeners.clear();
    vi.stubGlobal('location', location);
    vi.stubGlobal('window', window);
    const view = new View();
    return { view, stop: bindHash(view) };
  }

  afterEach(() => vi.unstubAllGlobals());

  it('reads the initial hash into the view', () => {
    const { view, stop } = setup('#/explore?q=abc&d=1');
    expect(view.q).toBe('abc');
    expect(view.d).toBe(true);
    stop();
  });

  it('replaces a non-canonical hash with the canonical one', () => {
    const { stop } = setup('');
    expect(location.replace).toHaveBeenCalledWith('#/overview');
    stop();
  });

  it('writes view changes to the hash', () => {
    const { view, stop } = setup('#/explore');
    view.q = 'x';
    flushSync();
    expect(location.hash).toBe(encode({ ...EMPTY, route: 'explore', q: 'x' }));
    stop();
  });

  it('pushes a new search and replaces a step to another event', () => {
    const { view, stop } = setup('#/explore?uid=1');
    location.replace.mockClear();
    view.uid = 2;
    flushSync();
    expect(location.replace).toHaveBeenCalledWith(encode({ ...EMPTY, route: 'explore', uid: 2 }));
    location.replace.mockClear();
    view.q = 'x';
    flushSync();
    expect(location.replace).not.toHaveBeenCalled();
    expect(location.hash).toBe(encode({ ...EMPTY, route: 'explore', q: 'x', uid: 2 }));
    stop();
  });

  it('replaces when told to, once', () => {
    const { view, stop } = setup('#/timeline');
    location.replace.mockClear();
    view.replaceNext = true;
    view.t = [1, 2];
    flushSync();
    expect(location.replace).toHaveBeenCalledTimes(1);
    view.t = [1, 3];
    flushSync();
    expect(location.replace).toHaveBeenCalledTimes(1);
    stop();
  });

  it('does not let a replace outlive a change that changed nothing', async () => {
    const { view, stop } = setup('#/timeline?t=1~2');
    view.replaceNext = true;
    view.t = view.t;
    flushSync();
    await new Promise((resolve) => setTimeout(resolve, 5));
    location.replace.mockClear();
    view.q = 'x';
    flushSync();
    expect(location.replace).not.toHaveBeenCalled();
    stop();
  });

  it('ignores a hashchange that carries the current state', () => {
    const { view, stop } = setup('#/explore?cols=A');
    const kept = view.cols;
    listeners.get('hashchange')?.();
    expect(view.cols).toBe(kept);
    stop();
  });

  it('removes its listener on cleanup', () => {
    const { stop } = setup('#/explore');
    expect(listeners.has('hashchange')).toBe(true);
    stop();
    expect(listeners.has('hashchange')).toBe(false);
  });
});
