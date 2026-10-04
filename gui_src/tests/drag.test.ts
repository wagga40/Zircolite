import { afterEach, describe, expect, it, vi } from 'vitest';
import { drag } from '../src/ui/drag';

class FakeTarget extends EventTarget {
  captured = new Set<number>();
  setPointerCapture(id: number) { this.captured.add(id); }
  hasPointerCapture(id: number) { return this.captured.has(id); }
  releasePointerCapture(id: number) { this.captured.delete(id); }
}

const pointer = (type: string, clientX: number, button = 0) => Object.assign(new Event(type), { clientX, button, pointerId: 1 });

function setup() {
  const keys = new EventTarget();
  vi.stubGlobal('window', keys);
  const target = new FakeTarget();
  const calls: string[] = [];
  const handlers = {
    move: (dx: number) => calls.push(`move ${dx}`),
    end: (dx: number) => calls.push(`end ${dx}`),
    click: () => calls.push('click'),
    cancel: () => calls.push('cancel'),
  };
  const start = (x: number, button = 0) => drag(pointer('pointerdown', x, button) as unknown as PointerEvent, target as unknown as HTMLElement, handlers);
  return { keys, target, calls, start };
}

afterEach(() => vi.unstubAllGlobals());

describe('drag', () => {
  it('treats a press that barely moved as a click', () => {
    const { target, calls, start } = setup();
    start(10);
    target.dispatchEvent(pointer('pointermove', 12));
    target.dispatchEvent(pointer('pointerup', 12));
    expect(calls).toEqual(['click']);
  });

  it('reports moves past the slop, then the end', () => {
    const { target, calls, start } = setup();
    start(10);
    target.dispatchEvent(pointer('pointermove', 30));
    target.dispatchEvent(pointer('pointerup', 30));
    expect(calls).toEqual(['move 20', 'end 20']);
    expect(target.captured.size).toBe(0);
  });

  it('ignores any button but the primary', () => {
    const { target, calls, start } = setup();
    start(10, 2);
    target.dispatchEvent(pointer('pointermove', 30));
    target.dispatchEvent(pointer('pointerup', 30));
    expect(calls).toEqual([]);
  });

  it('cancels on Escape and stops listening', () => {
    const { keys, target, calls, start } = setup();
    start(10);
    target.dispatchEvent(pointer('pointermove', 30));
    keys.dispatchEvent(Object.assign(new Event('keydown'), { key: 'Escape' }));
    target.dispatchEvent(pointer('pointerup', 40));
    expect(calls).toEqual(['move 20', 'cancel']);
  });

  it('cancels when the pointer capture is lost', () => {
    const { target, calls, start } = setup();
    start(10);
    target.dispatchEvent(pointer('pointermove', 30));
    target.dispatchEvent(new Event('lostpointercapture'));
    target.dispatchEvent(pointer('pointerup', 40));
    expect(calls).toEqual(['move 20', 'cancel']);
  });
});
