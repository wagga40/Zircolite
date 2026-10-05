import { describe, expect, it } from 'vitest';
import { levelInk, levelVar } from '../src/engine/levels';
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
