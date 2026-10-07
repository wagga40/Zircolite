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

  it('says why the committed search does not compile, for the search bar to show', () => {
    const query = new QueryState(schema, 6);
    expect(query.error).toBeNull();
    view.q = 'Comptuer:x';
    expect(query.error?.message).toContain('No field named Comptuer');
    expect(query.error?.start).toBe(0);
    view.q = 'Computer:x';
    expect(query.error).toBeNull();
  });

  it('puts bare words on the index while it loads and once it is ready, and back on the scan when it fails', () => {
    const query = new QueryState(schema, 6, true);
    view.q = 'powershell';
    for (const [status, indexed] of [['loading', true], ['ready', true], ['failed', false], ['absent', false]] as const) {
      textIndex.status = status;
      expect(query.where.includes('fulltext'), status).toBe(indexed);
    }
  });

  it('never puts bare words on an index the package does not have', () => {
    const query = new QueryState(schema, 6);
    view.q = 'powershell';
    textIndex.status = 'ready';
    expect(query.where).not.toContain('fulltext');
  });
});
