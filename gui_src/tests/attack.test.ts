import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { technique } from '../src/attack/catalog';
import {
  detectedTechniques, heatmap, heatmapSql, heatTerm, matrix, STORED_TECHNIQUES_SQL, techniqueCountsSql, unlisted,
} from '../src/attack/attack';
import { compile } from '../src/search/compile';
import { parse } from '../src/search/parse';
import { DETECTIONS_PREDICATE } from '../src/state/where';
import { type Fixture, openFixture, schema } from './fixture';

// Two more rules: one tagged with the parent T1059 (on event 3, already under T1033), one with T1562.001,
// which ATT&CK 19 revoked in favour of T1685 (on event 2, which nothing else detects).
const EXTRA = [
  `INSERT INTO rules VALUES
     (4, 'r-cmd', 'r-cmd', 'Command interpreter', 'low', 1, 'd', [], [], ['execution'], ['T1059'], 'x.yml', 'match', 0),
     (5, 'r-old', 'r-old', 'Old impair defenses', 'medium', 2, 'd', [], [], ['stealth'], ['T1562.001'], 'o.yml', 'match', 0)`,
  'INSERT INTO hits VALUES (4, 3), (5, 2)',
  'CREATE OR REPLACE TABLE event_levels AS SELECT h._zl_uid, max(r.level_rank) AS _zl_lvl FROM hits h JOIN rules r ON r.rule_idx = h.rule_idx GROUP BY h._zl_uid',
];

let db: Fixture;
let counts: Map<string, number>;
beforeAll(async () => {
  db = await openFixture(EXTRA);
  counts = new Map((await db.rows(techniqueCountsSql('TRUE'))).map((r) => [r.id as string, r.events as number]));
});
afterAll(() => db.close());

describe('technique counts', () => {
  it('counts a parent once for its own and its sub-techniques\' events', () => {
    // T1059.001 on 4294967297, T1059 on 3.
    expect(counts.get('T1059.001')).toBe(1);
    expect(counts.get('T1059')).toBe(2);
    expect(counts.get('T1053')).toBe(1);
  });

  it('every technique count is exactly what technique: lists', async () => {
    for (const [id, events] of counts) {
      expect((await db.uids(compile(parse(`technique:${id}`), schema))).length, id).toBe(events);
    }
  });
});

describe('the matrix', () => {
  it('shows a technique under every tactic it belongs to, with one count', () => {
    const columns = matrix(counts, 'detected');
    const under = columns.filter((c) => c.cells.some((cell) => cell.id === 'T1053')).map((c) => c.tactic);
    expect([...under].sort()).toEqual([...(technique('T1053')?.tactics ?? [])].sort());
    const execution = columns.find((c) => c.tactic === 'execution');
    const interpreter = execution?.cells.find((cell) => cell.id === 'T1059');
    expect(interpreter?.events).toBe(2);
    expect(interpreter?.subs.map((s) => [s.id, s.events])).toEqual([['T1059.001', 1]]);
  });

  it('lists only detected techniques unless asked for the full matrix', () => {
    const detected = matrix(counts, 'detected');
    expect(detected.every((c) => c.cells.every((cell) => cell.events > 0))).toBe(true);
    const full = matrix(counts, 'full');
    expect(full.find((c) => c.tactic === 'reconnaissance')?.cells.length).toBeGreaterThan(0);
    expect(full.find((c) => c.tactic === 'reconnaissance')?.cells.every((cell) => cell.events === 0)).toBe(true);
  });

  it('counts detected techniques once, however many tactics they sit under', () => {
    expect(detectedTechniques(counts)).toBe(['T1059', 'T1078', 'T1033', 'T1053'].length);
  });
});

describe('tags the catalogue does not list', () => {
  it('lists them with their replacement, never drops them', async () => {
    const stored = (await db.rows(STORED_TECHNIQUES_SQL)).map((r) => r.id as string);
    expect(unlisted(stored, counts)).toEqual([
      { id: 'T1562.001', events: 1, replacement: technique('T1685'), status: 'revoked' },
    ]);
  });
});

describe('the heatmap', () => {
  it('counts events with detections by UTC weekday and hour', async () => {
    const { cells, busiest } = heatmap((await db.rows(heatmapSql('TRUE'))) as { day: number; hour: number; events: number }[]);
    // Thursday 06:00: events 1, 2 and 3; 07:00: event 4294967297.
    expect(cells[3][6].events).toBe(3);
    expect(cells[3][7].events).toBe(1);
    expect(busiest).toBe(3);
    expect(cells.flat().filter((c) => c.events > 0)).toHaveLength(2);
  });

  it('a heatmap cell lists exactly its events', async () => {
    const term = compile(parse(heatTerm(4, 6)), schema);
    expect(await db.uids(`(${term}) AND (${DETECTIONS_PREDICATE})`)).toEqual([1, 2, 3]);
  });
});
