import { describe, expect, it } from 'vitest';
import { levelInk, levelVar } from '../src/engine/levels';
import { channels, contrast, deltaE, tokens } from './contrast';
import { levelName } from '../src/ui/format';

describe('level inks', () => {
  it('gives each Sigma level its ink, and an unknown level its own', () => {
    expect(levelVar(0)).toBe('--sev-0');
    expect(levelVar(4)).toBe('--sev-4');
    expect(levelVar(-1)).toBe('--sev-unknown');
    expect(levelVar(5)).toBe('--sev-unknown');
    expect(levelVar(null)).toBe('--sev-unknown');
    expect(levelVar(Number.NaN)).toBe('--sev-unknown');
    expect(levelVar(2.5)).toBe('--sev-unknown');
    expect(levelVar(-2)).toBe('--sev-unknown');
    expect(levelInk(3)).toBe('var(--sev-3)');
    expect(levelInk(-1)).toBe('var(--sev-unknown)');
  });

  it('names an unknown level', () => {
    expect(levelName(-1)).toBe('unknown');
    expect(levelName(null)).toBeNull();
    expect(levelName(2)).toBe('medium');
  });
});

describe('the unknown level ink', () => {
  it('stands apart from informational and every other level, and from the panel, in both themes', () => {
    for (const theme of ['light', 'dark'] as const) {
      const t = tokens(theme);
      const unknown = channels(t['--sev-unknown'] ?? '#000000');
      expect(t['--sev-unknown'], theme).toMatch(/^#/);
      expect(contrast(unknown, channels(t['--sev-0'])), theme).toBeGreaterThanOrEqual(1.8);
      expect(contrast(unknown, channels(t['--panel'])), theme).toBeGreaterThanOrEqual(3);
      for (const rank of [0, 1, 2, 3, 4]) expect(deltaE(unknown, channels(t[`--sev-${rank}`])), `${theme} --sev-${rank}`).toBeGreaterThan(40);
    }
  });
});
