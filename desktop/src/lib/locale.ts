/** WebKit may expose the POSIX locale as "C", which Intl rejects. Normalize
 * it before chart libraries read navigator.language during module loading. */
export function ensureNavigatorLocale(browser: Pick<Navigator, "language">): void {
  try {
    new Intl.NumberFormat(browser.language);
  } catch (error) {
    if (!(error instanceof RangeError)) throw error;
    Object.defineProperty(browser, "language", { configurable: true, value: "en-US" });
  }
}

if (typeof navigator !== "undefined") ensureNavigatorLocale(navigator);
