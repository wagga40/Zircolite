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
});
