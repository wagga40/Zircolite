import { describe, expect, it, vi } from 'vitest';
import { openTables } from '../src/engine/boot';
import type { PackageFile } from '../src/engine/manifest';

vi.mock('@duckdb/duckdb-wasm', () => ({}));

const names = ['events', 'rules', 'hits', 'alerts', 'alert_events'];
const file = (name: string, kind: PackageFile['kind'] = 'data'): PackageFile => ({
  name: name + '.parquet', kind, chunks: ['data/' + name + '.js'], bytes: 1, sha256: '',
});

describe('opening the Parquet tables', () => {
  it.each([false, true])('registers each table before reading the next, optional Explore file %s', async (indexed) => {
    const tables = indexed ? [...names, 'explore'] : names;
    const files = [...tables.map((name) => file(name)), file('text', 'index'), file('unrelated')];
    const steps: string[] = [];
    const queried: string[] = [];
    await openTables({ files }, async (entry) => {
      steps.push('read ' + entry.name);
      return new Uint8Array([1]);
    }, async (name, bytes) => {
      await Promise.resolve();
      expect([...bytes]).toEqual([1]);
      steps.push('registered ' + name);
    }, async (sql) => { queried.push(sql); });
    expect(steps).toEqual(tables.flatMap((name) => ['read ' + name + '.parquet', 'registered ' + name + '.parquet']));
    expect(queried).toEqual(tables.map((name) => name === 'explore'
      ? "CREATE VIEW explore AS SELECT *, file_row_number AS _zl_pos FROM read_parquet('explore.parquet', file_row_number=true)"
      : `CREATE VIEW ${name} AS SELECT * FROM read_parquet('${name}.parquet')`));
  });
});
