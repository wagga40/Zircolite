import { describe, expect, it } from 'vitest';
import { windowOf } from '../src/ui/virtual';

describe('the rows a list renders', () => {
  it('covers the viewport with overscan on each side', () => {
    expect(windowOf(0, 280, 1000)).toEqual({ first: 0, count: 18, top: 0 });
    expect(windowOf(2800, 280, 1000)).toEqual({ first: 92, count: 26, top: 92 * 28 });
  });

  it('stops at the end of the list', () => {
    expect(windowOf(28 * 995, 280, 1000)).toEqual({ first: 987, count: 13, top: 987 * 28 });
  });

  it('renders nothing for an empty list', () => {
    expect(windowOf(0, 280, 0)).toEqual({ first: 0, count: 0, top: 0 });
  });

  it('holds when the scroll position runs past either end or the viewport is empty', () => {
    expect(windowOf(100_000, 280, 10)).toEqual({ first: 9, count: 1, top: 9 * 28 });
    expect(windowOf(-50, 280, 1000)).toEqual({ first: 0, count: 17, top: 0 });
    expect(windowOf(0, 0, 1000)).toEqual({ first: 0, count: 8, top: 0 });
    expect(windowOf(0, 280, 1)).toEqual({ first: 0, count: 1, top: 0 });
  });
});
