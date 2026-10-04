import { afterEach, describe, expect, it } from 'vitest';
import { textIndex } from '../src/engine/textIndex.svelte';
import { EMPTY } from '../src/state/hash';
import { QueryState } from '../src/state/query.svelte';
import { view } from '../src/state/view.svelte';
import { schema } from './fixture';

afterEach(() => {
  view.apply(EMPTY);
  textIndex.status = 'absent';
});

describe('QueryState', () => {
  it('combines the search, the time range and Detections only', () => {
    const query = new QueryState(schema, 6);
    view.q = 'EventID:4624';
    view.t = [1, 2];
    view.d = true;
    expect(query.where).toContain('"EventID" = 4624');
    expect(query.where).toContain('make_timestamp(1000)');
    expect(query.where).toContain('FROM hits');
    expect(query.whereWithoutTime).not.toContain('make_timestamp');
  });

  it('matches nothing for a search that does not compile, never everything', () => {
    const query = new QueryState(schema, 6);
    view.q = 'Comptuer:x';
    expect(query.where).toBe('(FALSE)');
  });

  it('moves bare words onto the index once it is ready', () => {
    const query = new QueryState(schema, 6);
    view.q = 'powershell';
    expect(query.where).not.toContain('fulltext');
    textIndex.status = 'ready';
    expect(query.where).toContain('fulltext');
  });
});
