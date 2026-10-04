import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  entityField, tacticCells, tacticLabel, tacticsSql, tileEventsSql, tileRulesSql, tiles, topRulesSql,
} from '../src/overview/overview';
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
      { rank: 4, level: 'critical', events: 1, rules: 1 },
      { rank: 3, level: 'high', events: 0, rules: 1 },
      { rank: 2, level: 'medium', events: 1, rules: 1 },
      { rank: 1, level: 'low', events: 0, rules: 0 },
      { rank: 0, level: 'informational', events: 1, rules: 1 },
    ]);
  });

  it('applies the filters', async () => {
    expect(await db.rows(tileEventsSql(`"Computer" = 'WS02'`))).toEqual([{ rank: 2, events: 1 }, { rank: 4, events: 1 }]);
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
