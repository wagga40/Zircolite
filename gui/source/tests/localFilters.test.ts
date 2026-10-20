import { describe, expect, it } from 'vitest';
import { applyLocalCell, type LocalColumn, localCellText, localSchema, localWhere, sortClause } from '../src/ui/localFilters';

const COLUMNS: LocalColumn[] = [
  { name: 'v', type: 'text' },
  { name: 'events', type: 'number' },
  { name: 'first', type: 'time' },
];
const schema = localSchema(COLUMNS);
const [V, EVENTS, FIRST] = COLUMNS;
const JUNE_3 = Date.UTC(2021, 5, 3);

const applied = (filters: string, column: LocalColumn, text: string) => {
  const result = applyLocalCell(filters, column, text, schema);
  if ('problem' in result) throw new Error(result.problem);
  return result.query;
};

describe('local column filters', () => {
  it('filter a table\'s own columns with the cell syntax', () => {
    let filters = applied('', V, 'dc');
    filters = applied(filters, EVENTS, '>=10');
    expect(localWhere(filters, schema)).toBe(`("v" ILIKE '%dc%' AND "events" >= 10)`);
    expect(localCellText(filters, V)).toBe('dc');
    expect(localCellText(filters, EVENTS)).toBe('>=10');
    expect(localWhere('', schema)).toBe('TRUE');
  });

  it('read times as UTC dates, written as the table shows them', () => {
    const filters = applied('', FIRST, '>=2021-06-03 <2021-06-03 08:30');
    expect(localWhere(filters, schema)).toBe(`("first" >= ${JUNE_3} AND "first" < ${JUNE_3 + 8.5 * 3_600_000})`);
    expect(localCellText(filters, FIRST)).toBe('>=2021-06-03 <2021-06-03 08:30');
    expect(localCellText(applied('', FIRST, '>2021-06-03T08:30:15.5Z'), FIRST)).toBe('>2021-06-03 08:30:15.500');
    expect(localCellText(applied('', FIRST, '!*'), FIRST)).toBe('!*');
  });

  it.each([
    [FIRST, '2021', /Compare a time/],
    [FIRST, '>=yesterday', /written 2021-06-03/],
    [FIRST, '>=2021-13-40', /written 2021-06-03/],
    [EVENTS, '>=x', /needs a number/],
    [V, '>5', /holds text/],
  ] as const)('refuses %j %j', (column, text, message) => {
    expect(applyLocalCell('', column, text, schema)).toEqual({ problem: expect.stringMatching(message) });
  });

  it('keeps a name that shares a shortcut\'s a column of the table', () => {
    const host: LocalColumn = { name: 'host', type: 'text' };
    const own = localSchema([host]);
    const result = applyLocalCell('', host, 'x', own);
    expect('query' in result && localWhere(result.query, own)).toBe(`"host" ILIKE '%x%'`);
  });

  it('orders by a column, its missing values last, ties by the given key', () => {
    expect(sortClause({ column: 'events', desc: true }, ['"v"'])).toBe('"events" DESC NULLS LAST, "v"');
    expect(sortClause(null, ['"events" DESC', '"v"'])).toBe('"events" DESC, "v"');
  });
});
