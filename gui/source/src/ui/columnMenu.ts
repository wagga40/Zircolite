import type { Bound, ColumnFilter, ColumnState } from '../search/filters';

export type MenuOp = 'contains' | 'equals' | 'prefix' | 'suffix' | 'pattern' | 'present' | 'missing' | 'gt' | 'gte' | 'lt' | 'lte' | 'between';

export interface MenuForm {
  op: MenuOp;
  value: string;
  /** The upper end of a between. */
  value2: string;
  not: boolean;
}

const TEXT_OPS: readonly { value: MenuOp; label: string }[] = [
  { value: 'contains', label: 'contains' },
  { value: 'equals', label: 'equals' },
  { value: 'prefix', label: 'starts with' },
  { value: 'suffix', label: 'ends with' },
  { value: 'pattern', label: 'matches the pattern' },
  { value: 'present', label: 'has a value' },
  { value: 'missing', label: 'has no value' },
];

const NUMBER_OPS: readonly { value: MenuOp; label: string }[] = [
  { value: 'equals', label: '=' },
  { value: 'gt', label: '>' },
  { value: 'gte', label: '≥' },
  { value: 'lt', label: '<' },
  { value: 'lte', label: '≤' },
  { value: 'between', label: 'between' },
  { value: 'present', label: 'has a value' },
  { value: 'missing', label: 'has no value' },
];

const COMPARE: Record<string, MenuOp> = { '>': 'gt', '>=': 'gte', '<': 'lt', '<=': 'lte' };
const SYMBOL: Partial<Record<MenuOp, Bound['op']>> = { gt: '>', gte: '>=', lt: '<', lte: '<=' };

export function menuOps(numeric: boolean): readonly { value: MenuOp; label: string }[] {
  return numeric ? NUMBER_OPS : TEXT_OPS;
}

/** The form for a column's filter; one it cannot show starts empty, and applying replaces it. */
export function formFrom(state: ColumnState, numeric: boolean): MenuForm {
  const empty: MenuForm = { op: numeric ? 'equals' : 'contains', value: '', value2: '', not: false };
  if (state.kind !== 'filter') return empty;
  const filter = state.filter;
  switch (filter.op) {
    case 'contains':
    case 'equals':
    case 'prefix':
    case 'suffix':
    case 'pattern':
      return { ...empty, op: filter.op, value: filter.value, not: filter.negate };
    case 'present':
      return { ...empty, op: filter.negate ? 'missing' : 'present' };
    case 'compare': {
      const [first, second] = filter.bounds;
      if (!second) return { ...empty, op: COMPARE[first.op], value: first.value, not: filter.negate };
      if (first.op === '>=' && second.op === '<=') return { op: 'between', value: first.value, value2: second.value, not: filter.negate };
      return empty;
    }
    case 'oneOf':
      return empty;
  }
}

export function filterFrom(form: MenuForm): ColumnFilter | { problem: string } {
  if (form.op === 'present' || form.op === 'missing') return { op: 'present', negate: form.op === 'missing' };
  if (form.value === '') return { problem: 'Type a value to filter by' };
  if (form.op === 'between') {
    if (form.value2 === '') return { problem: 'A range needs both ends' };
    return { op: 'compare', bounds: [{ op: '>=', value: form.value.trim() }, { op: '<=', value: form.value2.trim() }], negate: form.not };
  }
  const symbol = SYMBOL[form.op];
  if (symbol) return { op: 'compare', bounds: [{ op: symbol, value: form.value.trim() }], negate: form.not };
  if (form.op === 'pattern') {
    if (!form.value.includes('*')) return { problem: 'A pattern needs a * where any characters may be' };
    if (/[\s"()]/.test(form.value)) return { problem: 'A pattern cannot hold spaces, quotes or parentheses; use contains or starts with instead' };
  }
  return { op: form.op as 'contains' | 'equals' | 'prefix' | 'suffix' | 'pattern', value: form.value, negate: form.not };
}
