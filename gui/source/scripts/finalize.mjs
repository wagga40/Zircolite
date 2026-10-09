// Completes gui/viewer/ after `vite build`: the page, the query engine, the
// Parquet extension, third-party notices, and viewer.json, which tells
// zircolite/package.py what to copy and what to wrap as script chunks.
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { gzip } from 'pako';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const out = path.resolve(root, '../viewer');
const dist = path.join(root, 'node_modules/@duckdb/duckdb-wasm/dist');
const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));

// The DuckDB inside @duckdb/duckdb-wasm 1.32.0. An extension only loads into
// the exact version it was built for, so both move together.
const DUCKDB_VERSION = 'v1.4.3';
const EXTENSION_URL = `https://extensions.duckdb.org/${DUCKDB_VERSION}/wasm_eh/parquet.duckdb_extension.wasm`;
const EXTENSION_SHA256 = '22765c8f7dc741cda2b571a66ac7bb355295d7d69a6c37e5315b265672984f55';

async function parquetExtension() {
  const cached = path.join(root, '.cache', `parquet-${DUCKDB_VERSION}.duckdb_extension.wasm`);
  if (!fs.existsSync(cached)) {
    const response = await fetch(EXTENSION_URL);
    if (!response.ok) throw new Error(`${EXTENSION_URL}: HTTP ${response.status}`);
    fs.mkdirSync(path.dirname(cached), { recursive: true });
    fs.writeFileSync(cached, Buffer.from(await response.arrayBuffer()));
  }
  const bytes = fs.readFileSync(cached);
  const digest = createHash('sha256').update(bytes).digest('hex');
  if (digest !== EXTENSION_SHA256) {
    fs.rmSync(cached);
    throw new Error(`the Parquet extension's SHA-256 is ${digest}, expected ${EXTENSION_SHA256}`);
  }
  return bytes;
}

function notices() {
  const listing = JSON.parse(execFileSync('npm', ['ls', '--omit=dev', '--all', '--json', '--long'], {
    cwd: root, encoding: 'utf8', shell: process.platform === 'win32', maxBuffer: 64 * 1024 * 1024,
  }));
  const seen = new Map();
  const walk = (node) => {
    for (const [name, dependency] of Object.entries(node.dependencies ?? {})) {
      if (dependency.path && dependency.version) seen.set(`${name}@${dependency.version}`, { name, ...dependency });
      walk(dependency);
    }
  };
  walk(listing);
  const sections = [...seen.values()].sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version)).map((entry) => {
    const licence = fs.readdirSync(entry.path).find((file) => /^(licen[cs]e|copying|notice)/i.test(file));
    const text = licence ? fs.readFileSync(path.join(entry.path, licence), 'utf8').trim() : `Licence: ${entry.license ?? 'unknown'}`;
    return `== ${entry.name} ${entry.version} (${entry.license ?? 'unknown'}) ==\n\n${text}`;
  });
  sections.push(`== DuckDB Parquet extension ${DUCKDB_VERSION} (MIT) ==\n\n` +
    `Downloaded from ${EXTENSION_URL}. It is part of DuckDB and shares the MIT licence of @duckdb/duckdb-wasm above.`);
  const attack = JSON.parse(fs.readFileSync(path.join(root, 'src/attack/catalog.json'), 'utf8'));
  sections.push(`== MITRE ATT&CK Enterprise ${attack.version} ==\n\n${attack.copyright}\n\n` +
    'Technique and tactic names, and where each technique sits, are reproduced from MITRE ATT&CK.\n\n' +
    fs.readFileSync(path.join(root, 'scripts/attack-terms.txt'), 'utf8').trim());
  return `Zircolite Viewer: third-party notices\n\n${sections.join('\n\n')}\n`;
}

fs.copyFileSync(path.join(root, 'index.html'), path.join(out, 'index.html'));
fs.copyFileSync(path.join(dist, 'duckdb-browser-eh.worker.js'), path.join(out, 'duckdb-browser-eh.worker.js'));
// pako, not node:zlib: zlib's output differs across Node builds and CPUs, and CI
// must rebuild these bytes exactly. A fixed time and OS keep the header the same too.
fs.writeFileSync(path.join(out, 'duckdb-eh.wasm.gz'), gzip(fs.readFileSync(path.join(dist, 'duckdb-eh.wasm')), { level: 9, header: { time: 0, os: 255 } }));
fs.writeFileSync(path.join(out, 'parquet.duckdb_extension.wasm'), await parquetExtension());
fs.writeFileSync(path.join(out, 'THIRD_PARTY_NOTICES.txt'), notices());
fs.writeFileSync(path.join(out, 'viewer.json'), JSON.stringify({
  data_format: 1,
  version: pkg.version,
  duckdb_wasm: pkg.dependencies['@duckdb/duckdb-wasm'],
  copy: ['index.html', 'app.js', 'app.css', 'THIRD_PARTY_NOTICES.txt'],
  wrap: ['duckdb-eh.wasm.gz', 'duckdb-browser-eh.worker.js', 'parquet.duckdb_extension.wasm'],
}, null, 2) + '\n');
console.log(`viewer written to ${out}`);
