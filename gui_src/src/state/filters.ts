import { type MosaicClient, Selection, type SelectionClause } from '@uwdata/mosaic-core';
import { verbatim } from '@uwdata/mosaic-sql';
import { DETECTIONS_PREDICATE } from './where';

/** Every filter of the page; a client named in a clause is not filtered by it. */
export const filters = Selection.crossfilter();

/** Clients that draw the time axis themselves, so the time brush must not filter them. */
export const timeClients = new Set<MosaicClient>();

const SEARCH = { reset: () => undefined };
const TIME = { reset: () => undefined };
const DETECTIONS = { reset: () => undefined };

function clause(source: object, predicate: string | null, clients?: Set<MosaicClient>): SelectionClause {
  return {
    source,
    clients,
    fields: [],
    value: predicate,
    predicate: predicate === null ? null : verbatim(predicate),
    meta: { type: 'match' },
  };
}

export function setSearch(predicate: string | null): void {
  filters.update(clause(SEARCH, predicate));
}

export function setTime(predicate: string | null): void {
  filters.update(clause(TIME, predicate, timeClients));
}

export function setDetections(on: boolean): void {
  filters.update(clause(DETECTIONS, on ? DETECTIONS_PREDICATE : null));
}
