/** The stacked fields and whether events without them count, kept while the person moves between views. */
export const stackChoice = $state<{ fields: string[] | null; missing: boolean }>({ fields: null, missing: false });
