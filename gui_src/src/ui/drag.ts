export interface DragHandlers {
  /** The horizontal distance from the press, in CSS pixels, once past the slop. */
  move(dx: number, event: PointerEvent): void;
  end(dx: number, event: PointerEvent): void;
  click(event: PointerEvent): void;
  cancel(): void;
}

const SLOP = 3;

/**
 * One pointer gesture: primary button only, captured so it survives leaving
 * the element, a click when it barely moved, and cancelled by Escape. Both
 * the strip and the timeline use it, so they behave alike.
 */
export function drag(start: PointerEvent, target: HTMLElement, handlers: DragHandlers): void {
  if (start.button !== 0) return;
  target.setPointerCapture(start.pointerId);
  const x0 = start.clientX;
  let moved = false;
  const onMove = (event: Event) => {
    const dx = (event as PointerEvent).clientX - x0;
    if (Math.abs(dx) > SLOP) moved = true;
    if (moved) handlers.move(dx, event as PointerEvent);
  };
  const onUp = (event: Event) => {
    finish();
    if (moved) handlers.end((event as PointerEvent).clientX - x0, event as PointerEvent);
    else handlers.click(event as PointerEvent);
  };
  const onCancel = () => {
    finish();
    handlers.cancel();
  };
  const onKey = (event: Event) => {
    if ((event as KeyboardEvent).key !== 'Escape') return;
    event.preventDefault();
    event.stopPropagation();
    onCancel();
  };
  function finish(): void {
    target.removeEventListener('pointermove', onMove);
    target.removeEventListener('pointerup', onUp);
    target.removeEventListener('pointercancel', onCancel);
    window.removeEventListener('keydown', onKey, true);
    if (target.hasPointerCapture(start.pointerId)) target.releasePointerCapture(start.pointerId);
  }
  target.addEventListener('pointermove', onMove);
  target.addEventListener('pointerup', onUp);
  target.addEventListener('pointercancel', onCancel);
  window.addEventListener('keydown', onKey, true);
}
