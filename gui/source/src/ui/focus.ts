/** What focus can land on once the drawer closes, in order of preference. Never the body, which takes none. */
export function focusFallback(opener: HTMLElement | null, doc: Pick<Document, 'querySelector' | 'getElementById'> = document): HTMLElement | null {
  if (opener?.isConnected) return opener;
  // Another view may have replaced the page the drawer opened from, and its grid with it.
  return (
    doc.getElementById('result-grid') ??
    doc.querySelector<HTMLElement>('main h1[tabindex="-1"]') ??
    doc.querySelector<HTMLElement>('nav[aria-label="Views"] [aria-current="page"]')
  );
}
