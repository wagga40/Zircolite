import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { totalSql } from '../src/detections/rules';
import { EVENT_LEVELS_SQL } from '../src/engine/sql';
import {
  entityField, tacticCells, tacticLabel, tacticsSql, tileEventsSql, tileRulesSql, tiles, topRulesSql,
} from '../src/overview/overview';
import { compile } from '../src/search/compile';
import { parse } from '../src/search/parse';
import { type Fixture, openFixture, schema, TACTICS } from './fixture';

let db: Fixture;
beforeAll(async () => { db = await openFixture(); });
afterAll(() => db.close());

describe('severity tiles', () => {
  it('counts each event once, at its highest level, with the rules behind each level', async () => {
    const events = await db.rows(tileEventsSql('TRUE'));
    const rules = await db.rows(tileRulesSql('TRUE'));
    expect(events).toEqual([{ rank: 0, events: 1 }, { rank: 2, events: 1 }, { rank: 4, events: 1 }]);
    expect(tiles(events as never, rules as never)).toEqual([
      { rank: 4, level: 'critical', label: 'Critical', term: 'level:critical', events: 1, rules: 1 },
      { rank: 3, level: 'high', label: 'High', term: 'level:high', events: 0, rules: 1 },
      { rank: 2, level: 'medium', label: 'Medium', term: 'level:medium', events: 1, rules: 1 },
      { rank: 1, level: 'low', label: 'Low', term: 'level:low', events: 0, rules: 0 },
      { rank: 0, level: 'informational', label: 'Informational', term: 'level:informational', events: 1, rules: 1 },
    ]);
  });

  it('applies the filters', async () => {
    expect(await db.rows(tileEventsSql(`"Computer" = 'WS02'`))).toEqual([{ rank: 2, events: 1 }, { rank: 4, events: 1 }]);
  });
});

describe('a rule without a known level', () => {
  // Event 2 is detected only by a rule whose level is not one of Sigma's, which package.py ranks -1.
  let odd: Fixture;
  beforeAll(async () => {
    odd = await openFixture([
      `INSERT INTO rules VALUES (4, 'r-odd', 'r-odd', 'Odd level', 'urgent', -1, 'd', [], [], [], [], 'o.yml', 'match', 0)`,
      'INSERT INTO hits VALUES (4, 2)',
      EVENT_LEVELS_SQL.replace('CREATE OR REPLACE TEMP TABLE', 'CREATE OR REPLACE TABLE'),
    ]);
  });
  afterAll(() => odd.close());

  it('gets an Unknown level tile, so the tiles add up to every event with a detection', async () => {
    const shown = tiles((await odd.rows(tileEventsSql('TRUE'))) as never, (await odd.rows(tileRulesSql('TRUE'))) as never);
    expect(shown.at(-1)).toEqual({ rank: -1, level: 'unknown', label: 'Unknown level', term: 'level:<informational', events: 1, rules: 1 });
    const [total] = await odd.rows(totalSql('TRUE'));
    expect(total.events).toBe(4);
    expect(shown.reduce((sum, tile) => sum + tile.events, 0)).toBe(total.events);
  });

  it('lists exactly its events when clicked', async () => {
    const shown = tiles((await odd.rows(tileEventsSql('TRUE'))) as never, []);
    for (const tile of shown) {
      expect(await odd.uids(compile(parse(tile.term), schema)), tile.label).toHaveLength(tile.events);
    }
    expect(await odd.uids(compile(parse('level:<informational'), schema))).toEqual([2]);
  });

  it('has no tile when no event is detected only at an unknown level', async () => {
    expect(tiles((await db.rows(tileEventsSql('TRUE'))) as never, []).map((tile) => tile.rank)).toEqual([4, 3, 2, 1, 0]);
  });
});

describe('tactics', () => {
  it('counts events per tactic and lays every tactic out in kill-chain order', async () => {
    const rows = await db.rows(tacticsSql('TRUE'));
    const cells = tacticCells(TACTICS, rows as never);
    expect(cells).toHaveLength(TACTICS.length);
    expect(cells.filter((c) => c.events > 0).map((c) => c.tactic)).toEqual(['initial-access', 'execution', 'persistence', 'discovery']);
    expect(cells.find((c) => c.tactic === 'execution')?.share).toBe(1);
    expect(cells.find((c) => c.tactic === 'impact')?.share).toBe(0);
  });

  it('names tactics in sentence case', () => {
    expect([tacticLabel('command-and-control'), tacticLabel('initial-access'), tacticLabel('stealth')]).toEqual([
      'Command and control', 'Initial access', 'Stealth',
    ]);
  });
});

describe('top rules and entities', () => {
  it('ranks rule keys by their events, counted once', async () => {
    expect(await db.rows(topRulesSql('TRUE', 3))).toEqual([
      { key: 'r-crit', title: 'Critical thing', rank: 4, events: 1 },
      { key: 'r-enc', title: 'Encoded PowerShell - Sysmon', rank: 3, events: 1 },
      { key: 'r-logon', title: 'Successful logon', rank: 0, events: 1 },
    ]);
  });

  it('finds the host and user fields this package has', () => {
    expect(entityField('host', schema)?.name).toBe('Computer');
    expect(entityField('user', schema)?.name).toBe('TargetUserName');
  });
});
