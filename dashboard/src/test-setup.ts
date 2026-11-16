import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

// Without Vitest globals, Testing Library can't clean up on its own, and renders would pile up.
afterEach(() => cleanup());

// jsdom has no ResizeObserver, which the virtual list and the charts use to measure themselves.
class ResizeObserverStub {
  observe(): void {}
  unobserve(): void {}
  disconnect(): void {}
}
globalThis.ResizeObserver ??= ResizeObserverStub as unknown as typeof ResizeObserver;
