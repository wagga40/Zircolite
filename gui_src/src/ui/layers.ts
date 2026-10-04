import { view } from '../state/view.svelte';
import { ui } from './ui.svelte';

export type Layer = 'dialog' | 'help' | 'menu' | 'drawer' | 'fields';

export interface OpenLayers {
  dialog: boolean;
  help: boolean;
  /** The phone Export menu, a popover over the table. */
  menu: boolean;
  drawer: boolean;
  /** The Fields panel as an overlay; on a wide screen it is part of the page, not a layer. */
  fields: boolean;
}

/**
 * The layer one Escape closes, in stacking order. Each Escape handler acts
 * only when its own layer is on top, so one press never closes two.
 */
export function topLayer(open: OpenLayers): Layer | null {
  if (open.dialog) return 'dialog';
  if (open.help) return 'help';
  if (open.menu) return 'menu';
  if (open.drawer) return 'drawer';
  if (open.fields) return 'fields';
  return null;
}

export function pageTopLayer(): Layer | null {
  return topLayer({
    dialog: document.querySelector('dialog[open]') !== null,
    help: ui.help,
    // Hidden on wide screens, where the two buttons show instead.
    menu: (document.querySelector('details.export-menu[open]')?.getClientRects().length ?? 0) > 0,
    drawer: view.uid !== null,
    fields: ui.fieldsOpen && matchMedia('(max-width: 720px)').matches,
  });
}
