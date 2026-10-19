import { describe, expect, it } from 'vitest';
import type { ColumnFilter } from '../src/search/filters';
import { filterFrom, formFrom, menuOps } from '../src/ui/columnMenu';

const shown = (filter: ColumnFilter) => ({ kind: 'filter' as const, filter, spans: [] as [number, number][] });

describe('the column menu form', () => {
  it('offers text and number operators', () => {
    expect(menuOps(false).map((o) => o.value)).toEqual(['contains', 'equals', 'prefix', 'suffix', 'pattern', 'present', 'missing']);
    expect(menuOps(true).map((o) => o.value)).toEqual(['equals', 'gt', 'gte', 'lt', 'lte', 'between', 'present', 'missing']);
  });

  it.each<[ColumnFilter, boolean]>([
    [{ op: 'contains', value: 'net user', negate: false }, false],
    [{ op: 'equals', value: 'cmd.exe', negate: true }, false],
    [{ op: 'prefix', value: 'C:\\', negate: false }, false],
    [{ op: 'suffix', value: '.exe', negate: false }, false],
    [{ op: 'pattern', value: 'C:*\\cmd*', negate: false }, false],
    [{ op: 'present', negate: false }, false],
    [{ op: 'present', negate: true }, true],
    [{ op: 'equals', value: '4624', negate: false }, true],
    [{ op: 'compare', bounds: [{ op: '>', value: '5' }], negate: true }, true],
    [{ op: 'compare', bounds: [{ op: '<=', value: '5' }], negate: false }, true],
    [{ op: 'compare', bounds: [{ op: '>=', value: '1' }, { op: '<=', value: '9' }], negate: false }, true],
  ])('shows %j and gives it back', (filter, numeric) => {
    expect(filterFrom(formFrom(shown(filter), numeric))).toEqual(filter);
  });

  it('starts empty for what the form cannot show', () => {
    expect(formFrom({ kind: 'none' }, false)).toEqual({ op: 'contains', value: '', value2: '', not: false });
    expect(formFrom({ kind: 'none' }, true).op).toBe('equals');
    expect(formFrom(shown({ op: 'oneOf', values: ['a', 'b'], negate: false }), false).value).toBe('');
    expect(formFrom(shown({ op: 'compare', bounds: [{ op: '>', value: '1' }, { op: '<', value: '9' }], negate: false }), true).value).toBe('');
    expect(formFrom({ kind: 'custom', text: 'x', spans: [] }, false).value).toBe('');
  });

  it.each([
    [{ op: 'contains', value: '', value2: '', not: false }, /Type a value/],
    [{ op: 'between', value: '1', value2: '', not: false }, /both ends/],
    [{ op: 'pattern', value: 'abc', value2: '', not: false }, /needs a \*/],
    [{ op: 'pattern', value: 'a* b', value2: '', not: false }, /cannot hold spaces/],
  ] as const)('refuses %j', (form, message) => {
    expect(filterFrom({ ...form })).toEqual({ problem: expect.stringMatching(message) });
  });
});
