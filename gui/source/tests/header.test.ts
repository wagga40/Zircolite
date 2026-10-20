import { describe, expect, it } from 'vitest';
import { applyCell, applyFilter, LEVEL_CHOICES, levelChoice, levelFilter, nextSort } from '../src/explore/header';
import { schema } from './fixture';

const field = (name: string) => {
  const found = schema.find(name);
  if (!found) throw new Error(name);
  return found;
};

describe('nextSort', () => {
  it('sorts by a new column ascending, and Level from the highest', () => {
    expect(nextSort(null, true, field('Image'))).toEqual({ sort: 'Image', desc: false });
    expect(nextSort(null, false, 'level')).toEqual({ sort: '_zl_level', desc: true });
  });

  it('turns the current sort around', () => {
    expect(nextSort(field('Image'), false, field('Image'))).toEqual({ sort: 'Image', desc: true });
    expect(nextSort(null, false, null)).toEqual({ sort: null, desc: true });
  });

  it('goes back to time order, oldest first', () => {
    expect(nextSort(field('Image'), true, null)).toEqual({ sort: null, desc: false });
  });
});

describe('the Level filter', () => {
  it.each([
    ['', ''],
    ['level:>=high', 'high'],
    ['x LEVEL:>=Medium', 'medium'],
    ['level:high', 'custom'],
    ['level:>=high level:<critical', 'custom'],
    ['"level":error', ''],
  ])('reads %j as %j', (query, choice) => {
    expect(levelChoice(query)).toBe(choice);
  });

  it('offers every level from the lowest, and writes each one back', () => {
    expect(LEVEL_CHOICES.map((c) => c.value)).toEqual(['', 'informational', 'low', 'medium', 'high', 'critical']);
    for (const { value } of LEVEL_CHOICES) {
      const filter = levelFilter(value);
      const query = applyFilter('x', 'level', filter, schema, { shortcut: true });
      expect('query' in query && levelChoice(query.query)).toBe(value);
    }
  });
});

describe('applyCell', () => {
  it('writes the typed filter into the search', () => {
    expect(applyCell('x', field('CommandLine'), 'net user', schema)).toEqual({ query: 'x CommandLine:*"net user"*' });
    expect(applyCell('x CommandLine:*a*', field('CommandLine'), '', schema)).toEqual({ query: 'x' });
    expect(applyCell('', field('EventID'), '>=1 <10', schema)).toEqual({ query: 'EventID:>=1 EventID:<10' });
  });

  it('says why text cannot be applied, and leaves the search alone', () => {
    expect(applyCell('x', field('Image'), 'a*b c', schema)).toEqual({ problem: expect.stringMatching(/cannot hold spaces/) });
    expect(applyCell('x', field('Image'), '>5', schema)).toEqual({ problem: expect.stringMatching(/holds text/) });
    expect(applyCell('Image:"open', field('Image'), 'x', schema)).toEqual({ problem: expect.stringMatching(/Fix the search/) });
  });
});
