import { describe, expect, it } from "vitest";
import { installNativeContextMenuGuard } from "../native-context-menu";

describe("native context menu guard", () => {
  it("prevents the browser menu but leaves other events alone", () => {
    const uninstall = installNativeContextMenuGuard(document);
    const rightClick = new MouseEvent("contextmenu", {
      bubbles: true,
      cancelable: true,
      button: 2,
    });
    document.body.dispatchEvent(rightClick);
    expect(rightClick.defaultPrevented).toBe(true);

    const leftClick = new MouseEvent("click", {
      bubbles: true,
      cancelable: true,
      button: 0,
    });
    document.body.dispatchEvent(leftClick);
    expect(leftClick.defaultPrevented).toBe(false);
    uninstall();
  });

  it("covers links, images, tables and inputs", () => {
    const uninstall = installNativeContextMenuGuard(document);
    for (const element of [
      document.createElement("a"),
      document.createElement("img"),
      document.createElement("table"),
      document.createElement("input"),
      document.createElement("textarea"),
    ]) {
      document.body.appendChild(element);
      const event = new MouseEvent("contextmenu", { bubbles: true, cancelable: true });
      element.dispatchEvent(event);
      expect(event.defaultPrevented).toBe(true);
    }
    uninstall();
  });

  it("stops intercepting after unmount", () => {
    const uninstall = installNativeContextMenuGuard(document);
    uninstall();
    const event = new MouseEvent("contextmenu", { bubbles: true, cancelable: true });
    document.body.dispatchEvent(event);
    expect(event.defaultPrevented).toBe(false);
  });
});
