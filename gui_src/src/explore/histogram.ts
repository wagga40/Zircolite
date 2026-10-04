export function formatRange([start, end]: [number, number]): string {
  const a = new Date(start).toISOString();
  const b = new Date(end).toISOString();
  const sameDay = a.slice(0, 10) === b.slice(0, 10);
  return `${a.slice(0, 10)} ${a.slice(11, 19)} to ${sameDay ? '' : `${b.slice(0, 10)} `}${b.slice(11, 19)}`;
}
