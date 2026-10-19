import { describe, expect, it } from 'vitest';
import type { Db } from '../src/engine/db';
import { LOGON_COLUMNS } from '../src/logons/logons';
import { LogonTable } from '../src/logons/table.svelte';

const noDb = { rows: () => Promise.reject(new Error('a table without its fields must not be asked')) } as unknown as Db;

describe('a logons table', () => {
  it('says it cannot be answered when the package lacks its fields, instead of loading for ever', () => {
    const table = new LogonTable(LOGON_COLUMNS);
    table.load(noDb, 'sessions', null);
    expect(table.unavailable).toBe(true);
  });

  it('is answerable again once it is asked a query', async () => {
    const table = new LogonTable<{ total: number }>(LOGON_COLUMNS);
    table.load(noDb, 'sessions', null);
    table.load({ rows: async () => [{ total: 1 }] } as unknown as Db, 'sessions', 'SELECT 1');
    expect(table.unavailable).toBe(false);
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(table.answer?.rows).toEqual([{ total: 1 }]);
  });
});
