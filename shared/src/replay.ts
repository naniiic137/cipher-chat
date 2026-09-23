/**
 * Replay protection. Every signed message carries a per-sender monotonically
 * increasing counter. Receivers keep, per sender key, the highest counter seen
 * and a sliding window of recent counters (to tolerate re-ordering). Anything
 * already seen, or older than the window, is rejected.
 */

export const REPLAY_WINDOW = 512;

export interface SenderWindow {
  max: number;
  seen: number[]; // counters within (max - REPLAY_WINDOW, max], ascending
}

export type ReplayState = Record<string, SenderWindow>;

export type ReplayVerdict = 'ok' | 'duplicate' | 'too-old';

/** Pure check (does not record). */
export function checkReplay(state: ReplayState, sender: string, ctr: number): ReplayVerdict {
  if (!Number.isSafeInteger(ctr) || ctr < 1) return 'too-old';
  const w = state[sender];
  if (!w) return 'ok';
  if (ctr > w.max) return 'ok';
  if (ctr <= w.max - REPLAY_WINDOW) return 'too-old';
  return w.seen.includes(ctr) ? 'duplicate' : 'ok';
}

/** Records a counter that passed checkReplay() and full authentication. */
export function recordCounter(state: ReplayState, sender: string, ctr: number): void {
  const w = (state[sender] ??= { max: 0, seen: [] });
  if (ctr > w.max) w.max = ctr;
  w.seen.push(ctr);
  w.seen.sort((a, b) => a - b);
  const floor = w.max - REPLAY_WINDOW;
  while (w.seen.length && w.seen[0]! <= floor) w.seen.shift();
}
