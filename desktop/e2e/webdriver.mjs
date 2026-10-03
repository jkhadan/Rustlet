// A small W3C WebDriver client, enough to drive the app through
// tauri-driver (which starts the app and proxies to WebKitWebDriver).
// No dependencies: the protocol is JSON over HTTP.
//
//   POST /session                          → { sessionId }
//   POST /session/:s/element  {using, value} → { "element-6066…": id }
//   POST /session/:s/element/:e/click
//   POST /session/:s/element/:e/value {text}
//   GET  /session/:s/element/:e/text
//   POST /session/:s/execute/sync {script, args}
//   GET  /session/:s/screenshot             → base64 PNG

import { writeFileSync } from "node:fs";

const ELEMENT = "element-6066-11e4-a52e-4f735466cecf";

export class WebDriver {
  constructor(base = "http://127.0.0.1:4444") {
    this.base = base;
    this.session = null;
  }

  async #call(method, path, body) {
    const res = await fetch(`${this.base}${path}`, {
      method,
      headers: { "content-type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const json = await res.json().catch(() => ({}));
    if (!res.ok) {
      const v = json.value ?? {};
      const e = new Error(`${method} ${path}: ${v.error ?? res.status}: ${v.message ?? ""}`);
      e.code = v.error;
      throw e;
    }
    return json.value;
  }

  #s(path) {
    return `/session/${this.session}${path}`;
  }

  /** Starts the app at `application` (an absolute path). */
  async start(application) {
    const v = await this.#call("POST", "/session", {
      capabilities: { alwaysMatch: { browserName: "wry", "tauri:options": { application } } },
    });
    this.session = v.sessionId;
  }

  async quit() {
    if (this.session) await this.#call("DELETE", this.#s("")).catch(() => {});
    this.session = null;
  }

  /** The first element matching `css`, waiting up to `timeout` ms for one. */
  async find(css, timeout = 10_000) {
    return this.waitFor(async () => {
      const v = await this.#call("POST", this.#s("/element"), { using: "css selector", value: css }).catch((e) => {
        if (e.code === "no such element") return null;
        throw e;
      });
      return v ? v[ELEMENT] : null;
    }, timeout, `an element ${css}`);
  }

  async findAll(css) {
    const v = await this.#call("POST", this.#s("/elements"), { using: "css selector", value: css });
    return v.map((e) => e[ELEMENT]);
  }

  async click(el) {
    await this.#call("POST", this.#s(`/element/${el}/click`), {});
  }

  async type(el, text) {
    await this.#call("POST", this.#s(`/element/${el}/value`), { text });
  }

  async text(el) {
    return this.#call("GET", this.#s(`/element/${el}/text`));
  }

  async attribute(el, name) {
    return this.#call("GET", this.#s(`/element/${el}/attribute/${name}`));
  }

  /** Runs `script` (a function body) in the page with `args`. */
  async exec(script, ...args) {
    return this.#call("POST", this.#s("/execute/sync"), { script, args });
  }

  /** Runs async `script`; it gets a `done` callback as its last argument. */
  async execAsync(script, ...args) {
    return this.#call("POST", this.#s("/execute/async"), { script, args });
  }

  async screenshot(path) {
    const b64 = await this.#call("GET", this.#s("/screenshot"));
    writeFileSync(path, Buffer.from(b64, "base64"));
  }

  /** Navigates the app's router (it uses `#/path` URLs). */
  async go(route) {
    await this.exec(`window.location.hash = arguments[0];`, route);
  }

  /** Polls `f` until it returns something truthy. */
  async waitFor(f, timeout = 10_000, what = "a condition") {
    const deadline = Date.now() + timeout;
    let last;
    for (;;) {
      try {
        const v = await f();
        if (v) return v;
      } catch (e) {
        last = e;
      }
      if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}${last ? ` (${last.message})` : ""}`);
      await new Promise((r) => setTimeout(r, 150));
    }
  }
}
