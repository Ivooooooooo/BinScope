







export function installNativeContextMenuGuard(target: Document | HTMLElement = document): () => void {
  const handler = (event: Event) => {
    event.preventDefault();
  };
  target.addEventListener("contextmenu", handler, { capture: true });
  return () => target.removeEventListener("contextmenu", handler, { capture: true });
}
