import * as duckdb from '@duckdb/duckdb-wasm';
import { blobToDataUrl, type ChunkStore, gunzip } from './chunks';
import type { Manifest, PackageFile } from './manifest';

export interface Engine {
  db: duckdb.AsyncDuckDB;
  conn: duckdb.AsyncDuckDBConnection;
}

export const TABLES = ['events', 'rules', 'hits', 'alerts', 'alert_events'] as const;

function find(manifest: Manifest, name: string): PackageFile {
  const file = manifest.files.find((entry) => entry.name === name);
  if (file === undefined) throw new Error(`the package has no ${name}`);
  return file;
}

export async function bootEngine(manifest: Manifest, store: ChunkStore, step: (label: string) => void): Promise<Engine> {
  const wasm = await gunzip(store.take(find(manifest, 'duckdb-eh.wasm.gz')), 'application/wasm');
  // A worker started from a file:// page cannot fetch a blob: URL in Chromium
  // or WebKit, but it can read a data: URL.
  const wasmUrl = await blobToDataUrl(wasm);
  const workerUrl = URL.createObjectURL(store.take(find(manifest, 'duckdb-browser-eh.worker.js'), 'text/javascript'));
  const db = new duckdb.AsyncDuckDB(new duckdb.VoidLogger(), new Worker(workerUrl));
  await db.instantiate(wasmUrl);
  URL.revokeObjectURL(workerUrl);
  step('Loading Parquet support');
  const conn = await db.connect();
  // DuckDB-WASM fetches Parquet support from extensions.duckdb.org. A data:
  // repository ending in '#' turns the path it appends into a fragment, so the
  // copy shipped in the package is loaded instead, offline.
  const extension = await blobToDataUrl(store.take(find(manifest, 'parquet.duckdb_extension.wasm'), 'application/wasm'));
  await conn.query(`SET custom_extension_repository = '${extension}#'`);
  await conn.query('LOAD parquet');
  await conn.query('SET parquet_metadata_cache = true');
  step('Opening the data');
  for (const table of TABLES) {
    const file = find(manifest, `${table}.parquet`);
    await db.registerFileBuffer(file.name, new Uint8Array(await store.take(file).arrayBuffer()));
    await conn.query(`CREATE VIEW ${table} AS SELECT * FROM read_parquet('${file.name}')`);
  }
  return { db, conn };
}
