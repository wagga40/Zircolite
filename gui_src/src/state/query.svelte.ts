import type { Schema } from '../engine/schema';
import { textIndex } from '../engine/textIndex.svelte';
import { compile } from '../search/compile';
import { type Node, parse } from '../search/parse';
import { SearchError } from '../search/tokens';
import { slowSearchNote } from '../ui/format';
import { view } from './view.svelte';
import { combineWhere, DETECTIONS_PREDICATE, timePredicate } from './where';

/** What every view filters by: the committed search, the time range and Detections only. */
export class QueryState {
  // A query from a bookmark has not been validated: an invalid one shows its
  // error in the search bar and matches nothing, never everything.
  compiled = $derived.by((): { tree: Node | null; sql: string | null } => {
    if (!view.q) return { tree: null, sql: null };
    try {
      const tree = parse(view.q);
      return { tree, sql: compile(tree, this.schema, { textIndex: textIndex.status === 'ready' }) };
    } catch (problem) {
      if (problem instanceof SearchError) return { tree: null, sql: 'FALSE' };
      throw problem;
    }
  });

  /** Every filter: what the table, facets, Detections and Overview read. */
  where = $derived(combineWhere([this.compiled.sql, timePredicate(view.t), view.d ? DETECTIONS_PREDICATE : null]));

  /** Every filter but time: the strip and the timeline draw time themselves. */
  whereWithoutTime = $derived(combineWhere([this.compiled.sql, view.d ? DETECTIONS_PREDICATE : null]));

  slow = $derived.by(() => slowSearchNote(this.compiled.tree, this.events, textIndex.status === 'ready'));

  constructor(
    readonly schema: Schema,
    readonly events: number,
  ) {}
}
