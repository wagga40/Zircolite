import { LEVELS } from '../engine/levels';
import type { Field, Schema } from '../engine/schema';
import { compile } from '../search/compile';
import { CellError, type ColumnFilter, type ColumnOptions, columnState, parseCell, setColumnFilter } from '../search/filters';
import { parse } from '../search/parse';
import { SearchError } from '../search/tokens';
import { LEVEL_SORT } from '../state/hash';
import type { SortKey } from './table';

/**
 * The order after a click on a header: the sorted column turns around, any
 * other starts ascending. Level starts from the highest, which is what a
 * person sorting by level looks for; Time goes back to oldest first.
 */
export function nextSort(current: SortKey | null, desc: boolean, target: SortKey | null): { sort: string | null; desc: boolean } {
  const sort = target === null ? null : target === 'level' ? LEVEL_SORT : target.name;
  if (target === current) return { sort, desc: !desc };
  return { sort, desc: target === 'level' };
}

export const LEVEL_CHOICES: readonly { value: string; label: string }[] = [
  { value: '', label: 'Any' },
  ...LEVELS.map((level, i) => ({ value: level, label: i === LEVELS.length - 1 ? 'Critical' : `${level[0].toUpperCase()}${level.slice(1)} and up` })),
];

const LEVEL: ColumnOptions = { shortcut: true };

/** The Level column's choice in the search: a level and up, none, or custom when the search says something else. */
export function levelChoice(query: string): string {
  const state = columnState(query, 'level', LEVEL);
  if (state.kind === 'none' || state.kind === 'invalid') return '';
  const filter = state.kind === 'filter' ? state.filter : null;
  if (filter?.op === 'compare' && !filter.negate && filter.bounds.length === 1 && filter.bounds[0].op === '>=') {
    const level = filter.bounds[0].value.toLowerCase();
    if ((LEVELS as readonly string[]).includes(level)) return level;
  }
  return 'custom';
}

export function levelFilter(choice: string): ColumnFilter | null {
  return choice === '' ? null : { op: 'compare', bounds: [{ op: '>=', value: choice }], negate: false };
}

export type Applied = { query: string } | { problem: string };

/** The search with a column's filter in place, or why it cannot take it: the search must still compile. */
export function applyFilter(query: string, name: string, filter: ColumnFilter | null, schema: Schema, options: ColumnOptions = {}): Applied {
  if (columnState(query, name, options).kind === 'invalid') return { problem: 'Fix the search first: it does not parse, so a column filter cannot change it' };
  const next = setColumnFilter(query, name, filter, options);
  try {
    compile(parse(next), schema);
  } catch (problem) {
    if (problem instanceof SearchError) return { problem: problem.message };
    throw problem;
  }
  return { query: next };
}

/** What typing in a field's filter cell does to the search. */
export function applyCell(query: string, field: Field, text: string, schema: Schema): Applied {
  let filter: ColumnFilter | null;
  try {
    filter = parseCell(text, field.type !== 'VARCHAR');
  } catch (problem) {
    if (problem instanceof CellError) return { problem: problem.message };
    throw problem;
  }
  return applyFilter(query, field.name, filter, schema);
}
