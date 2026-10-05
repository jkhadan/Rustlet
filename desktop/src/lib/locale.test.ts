// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";

const originalLanguage = Object.getOwnPropertyDescriptor(navigator, "language");
afterEach(() => {
  if (originalLanguage) Object.defineProperty(navigator, "language", originalLanguage);
  else Reflect.deleteProperty(navigator, "language");
  vi.resetModules();
});

describe("WebKit POSIX locales", () => {
  it.each(["C", "C.UTF-8", "en_US"])("the chart module loads with locale %s", async (language) => {
    Object.defineProperty(navigator, "language", { configurable: true, value: language });
    window.matchMedia ??= vi.fn(() => ({ matches: false, addEventListener() {}, removeEventListener() {} })) as unknown as typeof window.matchMedia;
    await expect(import("@/components/Chart")).resolves.toHaveProperty("Chart");
    expect(navigator.language).toBe("en-US");
  });

  it("preserves valid language preferences", async () => {
    const { ensureNavigatorLocale } = await import("./locale");
    const browser = { language: "de-DE" };
    ensureNavigatorLocale(browser);
    expect(browser.language).toBe("de-DE");
  });
});
