// Compare Explore's two query plans on the same package and the viewer's DuckDB-WASM engine.
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createDuckDB, NODE_RUNTIME, VoidLogger } from '@duckdb/duckdb-wasm/blocking';
import { createServer } from 'vite';

const [directory, option, ...extra] = process.argv.slice(2);
if (!directory || (option && option !== '--full') || extra.length) {
  console.error('usage: npm run wasm-pivots -- <extracted package directory> [--full]');
  process.exit(2);
}
const full = option === '--full';
const root = path.resolve(directory);
const require = createRequire(import.meta.url);

// Read the generated calls as JSON without executing the package's JavaScript.
function argsOf(relative, fn) {
  const target = path.resolve(root, relative);
  const within = path.relative(root, target);
  if (within === '..' || within.startsWith('..' + path.sep) || path.isAbsolute(within)) throw new Error('chunk is outside the package');
  const script = fs.readFileSync(target, 'utf8').trimEnd();
  const prefix = `__zircolite.${fn}(`;
  if (!script.startsWith(prefix) || !script.endsWith(');')) throw new Error(`invalid ${fn} script`);
  return JSON.parse(`[${script.slice(prefix.length, -2)}]`);
}

const [manifest] = argsOf('data/manifest.js', 'manifest');
function read(file) {
  const bytes = Buffer.alloc(file.bytes);
  let offset = 0;
  for (const [index, chunk] of file.chunks.entries()) {
    const [name, sequence, text] = argsOf(chunk, 'chunk');
    if (name !== file.name || sequence !== index) throw new Error(`unexpected chunk of ${file.name}`);
    const part = Buffer.from(text, 'base64');
    if (part.length > bytes.length - offset) throw new Error(`too many bytes for ${file.name}`);
    bytes.set(part, offset);
    offset += part.length;
  }
  if (offset !== file.bytes || createHash('sha256').update(bytes).digest('hex') !== file.sha256) {
    throw new Error(`incomplete or damaged ${file.name}`);
  }
  return bytes;
}

if (!manifest.files.some((f) => f.kind === 'data' && f.name === 'explore.parquet')) {
  throw new Error('this comparison needs a package created with --package-explore-index');
}

// Load the signed package extension synchronously, as the WASM worker does in a browser.
const extension = read(manifest.files.find((f) => f.name === 'parquet.duckdb_extension.wasm'));
const repository = 'data:application/wasm;base64,' + extension.toString('base64');
globalThis.XMLHttpRequest = class {
  open(method, url) {
    if (method !== 'GET' || url.split('#', 1)[0] !== repository) throw new Error('expected the embedded Parquet extension');
  }
  send() {
    this.status = 200;
    this.response = extension.buffer.slice(extension.byteOffset, extension.byteOffset + extension.byteLength);
  }
};
globalThis.fetch = () => { throw new Error('this benchmark reads local files only'); };

const wasm = (name) => ({ mainModule: require.resolve(`@duckdb/duckdb-wasm/dist/duckdb-${name}.wasm`) });
const db = await createDuckDB({ eh: wasm('eh'), mvp: wasm('mvp') }, new VoidLogger(), NODE_RUNTIME);
await db.instantiate();
const conn = db.connect();
const row = (sql) => conn.query(sql).toArray()[0];
const median = (values) => +[...values].sort((a, b) => a - b)[Math.floor(values.length / 2)].toFixed(2);

// Hash each ordered pair, independent of the Arrow batch boundaries chosen by the engine.
async function orderedDigest() {
  const digest = createHash('sha256');
  const reader = await conn.send('SELECT _zl_pos, _zl_uid FROM view_ids ORDER BY _zl_pos', true);
  for (const batch of reader) {
    const positions = batch.getChildAt(0).toArray();
    const uids = batch.getChildAt(1).toArray();
    const pairs = new BigInt64Array(2 * positions.length);
    for (let i = 0; i < positions.length; i++) {
      pairs[2 * i] = positions[i];
      pairs[2 * i + 1] = uids[i];
    }
    digest.update(new Uint8Array(pairs.buffer));
  }
  return digest.digest('hex');
}

// Use the viewer's TypeScript directly. Middleware mode with ws disabled opens no listening port.
const vite = await createServer({ configFile: false, root: fileURLToPath(new URL('..', import.meta.url)),
  server: { middlewareMode: true, ws: false, watch: null }, optimizeDeps: { noDiscovery: true } });
try {
  const [{ idsSql, COUNT_SQL, pageSql, PAGE }, { openTables }, { Schema }, { EVENT_LEVELS_SQL, ident },
    { compile }, { parse }, { quoteValue }, { findShortcut }, { timePredicate, combineWhere }] = await Promise.all(
    ['explore/table', 'engine/boot', 'engine/schema', 'engine/sql', 'search/compile', 'search/parse',
      'search/edit', 'search/shortcuts', 'state/where'].map((name) => vite.ssrLoadModule(`/src/${name}.ts`)),
  );
  conn.query(`SET custom_extension_repository = '${repository}#'`);
  conn.query('LOAD parquet');
  conn.query('SET parquet_metadata_cache = true');
  conn.query('SET autoinstall_known_extensions = false');
  conn.query('SET autoload_known_extensions = false');
  await openTables(manifest, read, (name, bytes) => db.registerFileBuffer(name, bytes), (sql) => conn.query(sql));
  conn.query(EVENT_LEVELS_SQL);

  const schema = Schema.fromManifest(manifest);
  const fields = ['Computer', 'Channel', 'EventID'].map((name) => schema.find(name)).filter(Boolean);
  const page = pageSql(fields, 0, PAGE);
  const counts = { events: manifest.totals.events, dated: manifest.parts.reduce((n, p) => n + p.events - p.time.missing - p.time.unparsed, 0) };
  const cases = [['all_asc', 'TRUE', false], ['all_desc', 'TRUE', true]];
  if (full) {
    const host = findShortcut('host').fields.map((name) => schema.find(name)).find((field) => field && field.count > 0);
    for (const [label, field] of [['host', host], ['Channel', schema.find('Channel')], ['EventID', schema.find('EventID')]]) {
      if (!field) continue;
      const key = ident(field.name);
      const top = row(`SELECT ${key}::VARCHAR AS v FROM events WHERE ${key}::VARCHAR <> '' GROUP BY 1 ORDER BY count(*) DESC, v LIMIT 1`);
      if (!top) continue;
      const query = `${label}:${quoteValue(top.v)}`;
      cases.push([label, combineWhere(compile(parse(query), schema, { matches: true })), true]);
    }
    if (counts.dated > 0) {
      const range = row('SELECT epoch_ms(quantile_disc(_zl_time, 0.75)) AS lo, epoch_ms(quantile_disc(_zl_time, 0.90)) AS hi FROM events');
      cases.push(['time', combineWhere(timePredicate([Number(range.lo), Number(range.hi) + 1])), true]);
    }
  }

  const runs = full ? 5 : 1;
  const report = { engine: row('SELECT version() AS v').v, events: counts.events, measured_runs: runs, pivots: [] };
  for (const [label, where, desc] of cases) {
    const elapsed = [[], []];
    let reference;
    for (let run = 0; run <= runs; run++) {
      for (const plan of run % 2 ? [1, 0] : [0, 1]) {
        const start = performance.now();
        conn.query(idsSql(where, desc, null, plan ? counts : undefined));
        const tally = row(COUNT_SQL);
        const rows = conn.query(page).toArray();
        if (run) elapsed[plan].push(performance.now() - start);
        if (run === 0) {
          const answer = { rows: tally.n, detected: tally.d, digest: await orderedDigest(),
            page: JSON.stringify(rows, (_, v) => typeof v === 'bigint' ? String(v) : v) };
          if (reference && JSON.stringify(reference) !== JSON.stringify(answer)) throw new Error(`${label}: results differ between query plans`);
          reference = answer;
        }
      }
    }
    report.pivots.push({ label, rows: reference.rows, ordered_sha256: reference.digest,
      baseline_ms: median(elapsed[0]), indexed_ms: median(elapsed[1]) });
  }
  console.log(JSON.stringify(report, null, 2));
} finally {
  conn.close();
  await vite.close();
}
