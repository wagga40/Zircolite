import { describe, expect, it } from 'vitest';
import { focusFallback } from '../src/ui/focus';

const el = (isConnected: boolean) => ({ isConnected }) as HTMLElement;
const doc = (found: Record<string, HTMLElement | null>) => ({
  getElementById: (id: string) => found[`#${id}`] ?? null,
  querySelector: (selector: string) => found[selector] ?? null,
}) as unknown as Document;

describe('focusFallback', () => {
  const grid = el(true);
  const heading = el(true);
  const tab = el(true);
  const found = { '#result-grid': grid, 'main h1[tabindex="-1"]': heading, 'nav[aria-label="Views"] [aria-current="page"]': tab };

  it('prefers the opener while it is in the page', () => {
    const opener = el(true);
    expect(focusFallback(opener, doc(found))).toBe(opener);
  });

  it('falls to the grid, then the heading, then the active tab', () => {
    expect(focusFallback(el(false), doc(found))).toBe(grid);
    expect(focusFallback(null, doc({ ...found, '#result-grid': null }))).toBe(heading);
    expect(focusFallback(null, doc({ ...found, '#result-grid': null, 'main h1[tabindex="-1"]': null }))).toBe(tab);
  });
});
