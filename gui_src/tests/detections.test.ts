import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  alertsSql, evidenceSql, groupKeysText, groupRules, type KeyRow, keyRowsSql, levelLabel, type RuleRow,
  ruleRowsSql, type SectionRow, sectionRowsSql, sections, totalSql,
} from '../src/detections/rules';
import { type Fixture, openFixture, schema } from './fixture';

// A Generic variant sharing r-enc's key and matching one more event, and a correlation rule with one alert.
const EXTRA = [
  `INSERT INTO rules VALUES (4, 'r-enc', 'r-enc', 'Encoded PowerShell - Generic', 'high', 3, 'd', [], [], ['execution'], ['T1059.001'], 'b.yml', 'match', 0)`,
  'INSERT INTO hits VALUES (4, 4294967297), (4, 3)',
  `INSERT INTO rules VALUES (5, 'r-corr', 'r-corr', 'Many logons', 'medium', 2, 'd', [], [], [], [], 'm.yml', 'correlation', 1)`,
  'INSERT INTO hits VALUES (5, 1), (5, 2)',
  `INSERT INTO alerts VALUES (0, 5, 0, 'a-1', '{"TargetUserName":"bob","Computer":"DC01"}', TIMESTAMP '2021-06-03 06:00:30',
     TIMESTAMP '2021-06-03 06:00:00', TIMESTAMP '2021-06-03 06:05:00', 'count', 2, 2, NULL)`,
  'INSERT INTO alert_events VALUES (0, 2, 2), (0, 1, 1)',
];

let db: Fixture;
beforeAll(async () => { db = await openFixture(EXTRA); });
afterAll(() => db.close());

const DC01 = `"Computer" = 'DC01'`;

describe('counts', () => {
  it('counts each entry\'s filtered events', async () => {
    const rows = (await db.rows(ruleRowsSql('TRUE'))) as unknown as RuleRow[];
    expect(rows.map((r) => [r.rule_idx, r.events])).toEqual([[0, 1], [1, 1], [2, 1], [3, 1], [4, 2], [5, 2]]);
    expect(rows[0].falsepositives).toEqual(['Admins']);
  });

  it('counts each key\'s events once', async () => {
    const keys = (await db.rows(keyRowsSql('TRUE'))) as unknown as KeyRow[];
    expect(Object.fromEntries(keys.map((k) => [k.key, k.events]))).toEqual({ 'r-enc': 2, 'r-logon': 1, 'r-whoami': 1, 'r-crit': 1, 'r-corr': 2 });
  });

  it('applies the filters', async () => {
    const keys = (await db.rows(keyRowsSql(DC01))) as unknown as KeyRow[];
    expect(Object.fromEntries(keys.map((k) => [k.key, k.events]))).toEqual({ 'r-logon': 1, 'r-corr': 2 });
    expect(await db.rows(totalSql(DC01))).toEqual([{ events: 1 }]);
  });

  it('counts a level\'s events once, at the level of each rule key', async () => {
    const rows = (await db.rows(sectionRowsSql('TRUE'))) as unknown as SectionRow[];
    expect(Object.fromEntries(rows.map((r) => [r.rank, r.events]))).toEqual({ 4: 1, 3: 2, 2: 3, 0: 1 });
  });
});

describe('grouping', () => {
  it('groups variants under their key, at their highest level, titled by the first entry', async () => {
    const rows = (await db.rows(ruleRowsSql('TRUE'))) as unknown as RuleRow[];
    const keys = (await db.rows(keyRowsSql('TRUE'))) as unknown as KeyRow[];
    const groups = groupRules(rows, keys);
    const enc = groups.find((g) => g.key === 'r-enc');
    expect(enc).toMatchObject({ title: 'Encoded PowerShell - Sysmon', rank: 3, events: 2, correlation: false });
    expect(enc?.variants.map((v) => v.rule_idx)).toEqual([0, 4]);
    expect(groups.find((g) => g.key === 'r-corr')?.correlation).toBe(true);
  });

  it('orders sections from critical down and hides rules without events unless asked', async () => {
    const rows = (await db.rows(ruleRowsSql(DC01))) as unknown as RuleRow[];
    const keys = (await db.rows(keyRowsSql(DC01))) as unknown as KeyRow[];
    const sectionRows = (await db.rows(sectionRowsSql(DC01))) as unknown as SectionRow[];
    const groups = groupRules(rows, keys);
    expect(sections(groups, sectionRows, false).map((s) => [s.rank, s.rules.map((g) => g.key)])).toEqual([
      [2, ['r-corr']],
      [0, ['r-logon']],
    ]);
    expect(sections(groups, sectionRows, true).map((s) => s.rank)).toEqual([4, 3, 2, 0]);
  });

  it('names levels, including a rule without one', () => {
    expect([levelLabel(4), levelLabel(0), levelLabel(-1)]).toEqual(['Critical', 'Informational', 'Unknown level']);
  });
});

describe('alerts', () => {
  it('lists a correlation rule\'s alerts with their window and metric', async () => {
    const rows = await db.rows(alertsSql([5]));
    expect(rows).toEqual([{
      alert_idx: 0, alert_id: 'a-1', group_keys: '{"TargetUserName":"bob","Computer":"DC01"}',
      occurrence: Date.UTC(2021, 5, 3, 6, 0, 30), window_start: Date.UTC(2021, 5, 3, 6), window_end: Date.UTC(2021, 5, 3, 6, 5),
      metric_name: 'count', metric_value: 2, event_count: 2, total: 1,
    }]);
    expect(await db.rows(alertsSql([]))).toEqual([]);
  });

  it('lists the evidence in its order, with host and event id', async () => {
    expect(await db.rows(evidenceSql(0, schema))).toEqual([
      { ord: 1, _zl_uid: 1, _zl_t: Date.UTC(2021, 5, 3, 6), host: 'DC01', eventid: '4624' },
      { ord: 2, _zl_uid: 2, _zl_t: Date.UTC(2021, 5, 3, 6, 0, 30), host: 'DC01', eventid: '4634' },
    ]);
  });

  it('shows group keys as text, whatever they hold', () => {
    expect(groupKeysText('{"TargetUserName":"bob","Computer":"DC01"}')).toBe('TargetUserName = bob, Computer = DC01');
    expect(groupKeysText('not json')).toBe('not json');
    expect(groupKeysText(null)).toBe('');
  });
});
