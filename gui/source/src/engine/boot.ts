import * as duckdb from '@duckdb/duckdb-wasm';
import { blobToDataUrl, type ChunkStore, gunzip } from './chunks';
import type { BootStep } from '../ui/loading';
import { hasExploreTable, type Manifest, type PackageFile } from './manifest';

export interface Engine {
  db: duckdb.AsyncDuckDB;
  conn: duckdb.AsyncDuckDBConnection;
}

const TABLES = ['events', 'rules', 'hits', 'alerts', 'alert_events'] as const;

function find(manifest: Pick<Manifest, 'files'>, name: string): PackageFile {
  const file = manifest.files.find((entry) => entry.name === name);
  if (file === undefined) throw new Error(`the package has no ${name}`);
  return file;
}

export async function openTables(
  manifest: Pick<Manifest, 'files'>,
  read: (file: PackageFile) => Promise<Uint8Array>,
  register: (name: string, bytes: Uint8Array) => Promise<void>,
  query: (sql: string) => Promise<unknown>,
): Promise<void> {
  const tables = hasExploreTable(manifest) ? [...TABLES, 'explore'] : TABLES;
  for (const table of tables) {
    const file = find(manifest, `${table}.parquet`);
    await register(file.name, await read(file));
    if (table === 'explore') {
      await query("CREATE VIEW explore AS SELECT *, file_row_number AS _zl_pos FROM read_parquet('explore.parquet', file_row_number=true)");
    } else {
      await query(`CREATE VIEW ${table} AS SELECT * FROM read_parquet('${file.name}')`);
    }
  }
}

export async function bootEngine(manifest: Manifest, store: ChunkStore, step: (label: BootStep) => void, loaded: (source: string) => void): Promise<Engine> {
  const wasm = await gunzip(store.take(find(manifest, 'duckdb-eh.wasm.gz')), 'application/wasm');
  // A worker started from a file:// page cannot fetch a blob: URL in Chromium
  // or WebKit, but it can read a data: URL.
  const wasmUrl = await blobToDataUrl(wasm);
  const workerUrl = URL.createObjectURL(store.take(find(manifest, 'duckdb-browser-eh.worker.js'), 'text/javascript'));
  const worker = new Worker(workerUrl);
  const db = new duckdb.AsyncDuckDB(new duckdb.VoidLogger(), worker);
  // A worker that fails to start never answers, so instantiate() would wait
  // forever; its error events must end the wait instead.
  let fail: (reason: Error) => void = () => {};
  const failed = new Promise<never>((_, reject) => {
    fail = reject;
  });
  const onError = (event: ErrorEvent) => fail(new Error(`the query engine's worker failed to start${event.message ? `: ${event.message}` : ''}`));
  const onMessageError = () => fail(new Error("the query engine's worker sent a message the page could not read"));
  worker.addEventListener('error', onError);
  worker.addEventListener('messageerror', onMessageError);
  try {
    await Promise.race([db.instantiate(wasmUrl), failed]);
  } catch (error) {
    worker.terminate();
    throw error;
  } finally {
    worker.removeEventListener('error', onError);
    worker.removeEventListener('messageerror', onMessageError);
    URL.revokeObjectURL(workerUrl);
  }
  step('Loading Parquet support');
  const conn = await db.connect();
  // DuckDB-WASM fetches Parquet support from extensions.duckdb.org. A data:
  // repository ending in '#' turns the path it appends into a fragment, so the
  // copy shipped in the package is loaded instead, offline.
  const extension = await blobToDataUrl(store.take(find(manifest, 'parquet.duckdb_extension.wasm'), 'application/wasm'));
  await conn.query(`SET custom_extension_repository = '${extension}#'`);
  await conn.query('LOAD parquet');
  await conn.query('SET parquet_metadata_cache = true');
  // Parquet is loaded from the package; any other extension would be fetched
  // from the repository set above and fail confusingly, so stop autoloading.
  await conn.query('SET autoinstall_known_extensions = false');
  await conn.query('SET autoload_known_extensions = false');
  step('Opening the data');
  await openTables(manifest, (file) => store.readBytes(file, loaded),
    (name, bytes) => db.registerFileBuffer(name, bytes), (sql) => conn.query(sql));
  return { db, conn };
}
