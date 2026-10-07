// Writes src/attack/catalog.json from MITRE's Enterprise ATT&CK STIX bundle:
//   node scripts/attack-catalog.mjs <enterprise-attack-X.Y.json>
// The viewer names techniques and places them under tactics from this file; a
// Sigma tag carries only an ID, and a rule's tactics and techniques are
// separate lists, so the placement cannot come from the rules.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const source = process.argv[2];
if (!source) {
  console.error('usage: node scripts/attack-catalog.mjs <enterprise-attack-X.Y.json>');
  process.exit(2);
}
const { objects } = JSON.parse(fs.readFileSync(source, 'utf8'));
const byRef = new Map(objects.map((o) => [o.id, o]));
const attackId = (o) => o?.external_references?.find((r) => r.source_name === 'mitre-attack')?.external_id;
const live = (o) => !o.revoked && !o.x_mitre_deprecated;

const collection = objects.find((o) => o.type === 'x-mitre-collection');
const matrix = objects.find((o) => o.type === 'x-mitre-matrix' && live(o));
const marking = objects.find((o) => o.type === 'marking-definition' && o.definition?.statement);
if (!collection || !matrix || !marking) throw new Error(`${source} is not an Enterprise ATT&CK bundle`);

const tactics = matrix.tactic_refs.map((ref) => byRef.get(ref)).map((t) => ({ shortname: t.x_mitre_shortname, id: attackId(t), name: t.name }));
const patterns = objects.filter((o) => o.type === 'attack-pattern' && attackId(o));
const techniques = patterns
  .filter(live)
  .map((o) => ({
    id: attackId(o),
    name: o.name,
    tactics: (o.kill_chain_phases ?? []).filter((p) => p.kill_chain_name === 'mitre-attack').map((p) => p.phase_name),
  }))
  .sort((a, b) => a.id.localeCompare(b.id));
const active = new Set(techniques.map((t) => t.id));

// A revoked ID points at what replaced it, through any chain of revocations.
const revokedBy = new Map();
for (const r of objects) {
  if (r.type !== 'relationship' || r.relationship_type !== 'revoked-by') continue;
  const from = attackId(byRef.get(r.source_ref));
  const to = attackId(byRef.get(r.target_ref));
  if (from && to && byRef.get(r.source_ref).type === 'attack-pattern') revokedBy.set(from, to);
}
const revoked = {};
for (const from of [...revokedBy.keys()].sort()) {
  let to = revokedBy.get(from);
  const seen = new Set([from]);
  while (to && !active.has(to) && revokedBy.has(to) && !seen.has(to)) {
    seen.add(to);
    to = revokedBy.get(to);
  }
  if (to && active.has(to)) revoked[from] = to;
}
const deprecated = patterns.filter((o) => o.x_mitre_deprecated && !o.revoked).map(attackId).sort();

const catalog = { version: collection.x_mitre_version, copyright: marking.definition.statement, tactics, techniques, revoked, deprecated };
fs.writeFileSync(path.join(root, 'src/attack/catalog.json'), `${JSON.stringify(catalog)}\n`);
console.log(`ATT&CK ${catalog.version}: ${tactics.length} tactics, ${techniques.length} techniques, ${Object.keys(revoked).length} revoked, ${deprecated.length} deprecated`);
