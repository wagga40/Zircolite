import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { suggestValuesSql } from '../src/explore/sidebar';
import { parse } from '../src/search/parse';
import { formatCount, inputCount, isoTime, levelName, slowSearchNote, timeRange } from '../src/ui/format';
import { topLayer } from '../src/ui/layers';
import { nextTheme } from '../src/ui/theme';
import { type Fixture, openFixture, schema } from './fixture';

let db: Fixture;
beforeAll(async () => { db = await openFixture(); });
afterAll(() => db.close());

describe('format', () => {
  it('formats counts, times and levels', () => {
    expect(formatCount(1868682)).toBe('1,868,682');
    expect(isoTime(Date.UTC(2021, 5, 3, 6, 36, 55, 123))).toBe('2021-06-03 06:36:55.123');
    expect(isoTime(null)).toBe('');
    expect(levelName(3)).toBe('high');
    expect(levelName(null)).toBeNull();
    expect(levelName(-1)).toBeNull();
  });

  it('counts inputs, not parts', () => {
    const parts = [{ sources: ['a', 'b'] }, { sources: ['b', 'c'] }];
    expect(inputCount({ parts })).toBe(3);
  });

  it('words the time range in UTC from microseconds', () => {
    const us = (ms: number) => ms * 1000;
    const parts = [
      { time: { min: us(Date.UTC(2021, 5, 3, 6, 0, 0)), max: us(Date.UTC(2021, 5, 3, 7, 0, 0)) } },
      { time: { min: us(Date.UTC(2021, 5, 2, 23, 59, 59)), max: us(Date.UTC(2021, 5, 3, 8, 0, 0)) } },
    ];
    expect(timeRange(parts)).toBe('2021-06-02 23:59:59 to 2021-06-03 08:00:00 UTC');
    expect(timeRange([{ time: { min: null, max: null } }])).toBe('No event has a time');
    expect(timeRange([])).toBe('No event has a time');
  });
});

describe('slow search note', () => {
  it('warns about a search of every field on a large package', () => {
    expect(slowSearchNote(parse('mimikatz'), 1_868_682)).toBe(
      'Searching every field of 1,868,682 events; this can take a minute. A field search such as CommandLine:*mimikatz* is much faster.',
    );
  });

  it('names the index when it is in use', () => {
    expect(slowSearchNote(parse('mimikatz'), 1_868_682, true)).toBe(
      'Searching every field of 1,868,682 events with the full-text index; this can take a few seconds.',
    );
  });

  it('stays quiet for field searches and for packages of 200,000 events or fewer', () => {
    expect(slowSearchNote(parse('CommandLine:*mimikatz*'), 1_868_682)).toBeNull();
    expect(slowSearchNote(parse('mimikatz'), 200_000)).toBeNull();
    expect(slowSearchNote(null, 1_868_682)).toBeNull();
  });
});

describe('theme', () => {
  it('cycles system, light, dark', () => {
    expect([nextTheme('system'), nextTheme('light'), nextTheme('dark')]).toEqual(['light', 'dark', 'system']);
  });
});

describe('value suggestions', () => {
  it('suggests values starting with the prefix, literally', async () => {
    const computer = schema.find('Computer');
    const image = schema.find('Image');
    expect(computer && image).toBeTruthy();
    expect(await db.rows(suggestValuesSql(computer!, 'd'))).toEqual([{ v: 'DC01' }]);
    expect(await db.rows(suggestValuesSql(image!, 'C:\\Tools\\50_'))).toEqual([{ v: 'C:\\Tools\\50_off.exe' }]);
    expect(await db.rows(suggestValuesSql(image!, 'C:\\Tools\\5%'))).toEqual([]);
  });
});

describe('Escape layers', () => {
  const none = { dialog: false, help: false, menu: false, drawer: false, fields: false };

  it('names the topmost open layer: dialog, help, the Export menu, drawer, then the Fields panel', () => {
    expect(topLayer({ dialog: true, help: true, menu: true, drawer: true, fields: true })).toBe('dialog');
    expect(topLayer({ ...none, help: true, drawer: true, fields: true })).toBe('help');
    expect(topLayer({ ...none, menu: true, drawer: true, fields: true })).toBe('menu');
    expect(topLayer({ ...none, drawer: true, fields: true })).toBe('drawer');
    expect(topLayer({ ...none, fields: true })).toBe('fields');
  });

  it('leaves Escape to the strip only when no layer is open', () => {
    expect(topLayer(none)).toBeNull();
  });
});
