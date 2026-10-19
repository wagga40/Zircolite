import type { Db } from '../engine/db';
import { type LocalColumn, type LocalSort, localSchema } from '../ui/localFilters';
import { Panel } from '../ui/panel.svelte';

/** One table of the view: its own column filters and order, and its rows for the question they answer. */
export class LogonTable<Row> {
  filters = $state('');
  sort = $state<LocalSort | null>(null);
  readonly list = new Panel<{ asked: string; rows: Row[] }>();
  readonly schema;
  /** The query the rows on screen must answer; the empty text when the package cannot be asked it. */
  asked = $state('');

  constructor(columns: LocalColumn[]) {
    this.schema = localSchema(columns);
  }

  get answer(): { asked: string; rows: Row[] } | null {
    return this.list.slot.data?.asked === this.asked ? this.list.slot.data : null;
  }

  load(db: Db, lane: string, sql: string | null): void {
    this.asked = sql ?? '';
    if (sql === null) return;
    this.list.load(async () => ({ asked: sql, rows: await db.rows<Row>(sql, { lane }) }));
  }
}
