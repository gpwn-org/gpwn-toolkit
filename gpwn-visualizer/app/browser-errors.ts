export const RESIZE_OBSERVER_LOOP_MESSAGE =
  "ResizeObserver loop completed with undelivered notifications";

export function isBenignResizeObserverError(event: unknown) {
  if (!event || typeof event !== "object") return false;
  const candidate = event as { message?: unknown; error?: { message?: unknown } };
  const message = typeof candidate.message === "string"
    ? candidate.message
    : typeof candidate.error?.message === "string" ? candidate.error.message : "";
  return message.includes(RESIZE_OBSERVER_LOOP_MESSAGE);
}

// This executes from <head> before the development error overlay listener.
export const EARLY_BROWSER_ERROR_GUARD = `(()=>{const expected=${JSON.stringify(RESIZE_OBSERVER_LOOP_MESSAGE)};window.addEventListener("error",event=>{const direct=event&&event.message;const nested=event&&event.error&&event.error.message;const message=typeof direct==="string"?direct:typeof nested==="string"?nested:"";if(!message.includes(expected))return;event.preventDefault();event.stopImmediatePropagation();},true);})();`;
