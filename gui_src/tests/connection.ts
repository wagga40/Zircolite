import type { Sender } from '../src/engine/queries';

type Row = Record<string, unknown>;

/** A connection whose queries finish when the test says so, one at a time like DuckDB-WASM's. */
export function fakeConnection() {
  const sent: string[] = [];
  let running: { finish(rows?: Row[]): void; fail(error: Error): void } | null = null;
  let cancels = 0;
  const sender: Sender = {
    send(sql: string) {
      sent.push(sql);
      return new Promise((resolve, reject) => {
        running = {
          finish(rows = []) {
            running = null;
            resolve((async function* () {
              yield { toArray: () => rows.map((row) => ({ toJSON: () => row })) };
            })());
          },
          fail(error) {
            running = null;
            reject(error);
          },
        };
      });
    },
    async cancelSent() {
      cancels += 1;
      running?.fail(new Error('query was canceled'));
      return true;
    },
  };
  const tick = () => new Promise((resolve) => setTimeout(resolve, 0));
  return {
    sender,
    sent,
    cancels: () => cancels,
    async finish(rows?: Row[]) {
      await tick();
      if (!running) throw new Error('no query is running');
      running.finish(rows);
      await tick();
    },
    async fail(error: Error) {
      await tick();
      running?.fail(error);
      await tick();
    },
  };
}
