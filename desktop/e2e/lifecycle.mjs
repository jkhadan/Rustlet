// Phase 6's milestone, as a script: a container's whole life driven from
// the GUI, with the `rustlet` CLI acting on the same daemon at the same
// time, each side seeing what the other did without a reload.
//
//   node e2e/lifecycle.mjs <app binary> <rustlet CLI> [screenshot dir]
//
// Needs a daemon this user may use (RUSTLET_HOST, else the default
// socket), the alpine image, and tauri-driver listening on :4444 (see
// desktop/README.md). With E2E_RESTART set to a shell command that
// restarts the daemon, it also checks that the app reconnects.
// Containers are named e2e-*; whatever a failed run leaves is removed at
// the start of the next.

import { execFileSync } from "node:child_process";

import { WebDriver } from "./webdriver.mjs";

const [app, cli, shots] = process.argv.slice(2);
if (!app || !cli) {
  console.error("usage: node e2e/lifecycle.mjs <app binary> <rustlet CLI> [screenshot dir]");
  process.exit(2);
}

/** Runs the CLI; its stdout, or null if it failed. */
function rustlet(...args) {
  try {
    return execFileSync(cli, args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  } catch {
    return null;
  }
}

const status = (name) => {
  const out = rustlet("inspect", name);
  return out ? JSON.parse(out)[0].state.status : null;
};

const d = new WebDriver();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let step = 0;
async function check(what, f) {
  step++;
  const t = Date.now();
  try {
    await f();
    console.log(`  ✓ ${step}. ${what} (${Date.now() - t} ms)`);
    if (shots) await d.screenshot(`${shots}/e2e-${String(step).padStart(2, "0")}.png`);
  } catch (e) {
    console.log(`  ✗ ${step}. ${what}: ${e.message}`);
    if (shots) await d.screenshot(`${shots}/e2e-failed.png`).catch(() => {});
    throw e;
  }
}

/** The GUI's row for container `name`, and its status. */
const rowStatus = (name) =>
  d.exec(
    `const r = document.querySelector('[data-testid="container-row"][data-name="' + arguments[0] + '"]');
     return r ? r.dataset.status : null;`,
    name,
  );

for (const n of ["e2e-cli", "e2e-gui"]) rustlet("rm", "-f", n);
rustlet("network", "rm", "e2e-net");
rustlet("volume", "rm", "e2e-vol");

console.log("lifecycle:");
await d.start(app);
try {
  await check("the app connects to the daemon", async () => {
    await d.find('[data-testid="connection"][data-state="connected"]', 20_000);
  });

  await check("a container the CLI runs appears in the list, running", async () => {
    await d.go("/containers");
    await d.find('[data-testid="containers-table"], [data-testid="open-run"]');
    if (!rustlet("run", "-d", "--name", "e2e-cli", "alpine", "sleep", "1000")) throw new Error("rustlet run failed");
    await d.waitFor(async () => (await rowStatus("e2e-cli")) === "running", 5_000, "e2e-cli running in the list");
  });

  await check("the run dialog creates and starts a container", async () => {
    await d.click(await d.find('[data-testid="open-run"]'));
    await d.type(await d.find('input[name="image"]'), "alpine");
    await d.type(await d.find('input[name="name"]'), "e2e-gui");
    await d.type(await d.find('input[name="command"]'), `sh -c "echo hello from the gui; exec sleep 1000"`);
    await d.click(await d.find('[data-testid="run-submit"]'));
    // The app opens the new container's page.
    await d.waitFor(async () => (await d.text(await d.find('[data-testid="container-name"]'))) === "e2e-gui", 20_000, "its page");
    await d.waitFor(() => status("e2e-gui") === "running", 5_000, "the CLI to see it running");
  });

  await check("its log shows what it printed", async () => {
    await d.click(await d.findXPath(`//button[@role="tab"][contains(., "Logs")]`));
    await d.waitFor(
      async () => (await d.text(await d.find('[data-testid="logs"]'))).includes("hello from the gui"),
      10_000,
      "the line in the log view",
    );
  });

  await check("the terminal runs a shell in it", async () => {
    await d.click(await d.findXPath(`//button[@role="tab"][contains(., "Terminal")]`));
    await d.find('[data-testid="terminal-state"][data-state="open"]', 15_000);
    await sleep(500);
    await d.type(await d.find(".xterm-helper-textarea"), "echo answer=$((6*7))");
    await d.waitFor(
      () => d.exec(`return document.querySelector('.xterm-rows')?.textContent ?? ''`).then((t) => t.includes("answer=42")),
      10_000,
      "answer=42 on the terminal",
    );
    // Its shell, as the CLI sees it (what the next step expects gone).
    if (!/\bsh\b/.test(rustlet("exec", "e2e-gui", "ps", "-o", "comm") ?? "")) throw new Error("no sh in the container");
  });

  await check("leaving the terminal hangs its shell up (SIGHUP), leaving no shell behind", async () => {
    await d.click(await d.findXPath(`//button[@role="tab"][contains(., "Overview")]`));
    // The container's own process is `sleep` (its sh exec'd it): any sh is
    // a terminal's.
    await d.waitFor(() => !/\bsh\b/.test(rustlet("exec", "e2e-gui", "ps", "-o", "comm") ?? "sh"), 5_000, "no sh in the container");
  });

  await check("pausing from the GUI freezes it (as the CLI sees it), resuming thaws it", async () => {
    await d.click(await d.button("Pause"));
    await d.waitFor(() => status("e2e-gui") === "paused", 5_000, "paused");
    await d.click(await d.button("Resume"));
    await d.waitFor(() => status("e2e-gui") === "running", 5_000, "running again");
  });

  await check("the isolation inspector reads its namespaces", async () => {
    await d.click(await d.findXPath(`//button[@role="tab"][contains(., "Isolation")]`));
    await d.find('[data-testid="namespaces"] [data-kind="pid"][data-shared-with-host="false"]', 10_000);
  });

  await check("a stop by the CLI shows on its page at once", async () => {
    if (rustlet("stop", "-t", "1", "e2e-gui") == null) throw new Error("rustlet stop failed");
    await d.waitFor(
      async () => (await d.text(await d.find('[data-testid="container-status"]'))).startsWith("Exited"),
      5_000,
      "Exited on the page",
    );
  });

  await check("starting it from the GUI runs it again", async () => {
    await d.click(await d.button("Start"));
    await d.waitFor(() => status("e2e-gui") === "running", 10_000, "running");
  });

  await check("removing it from the GUI removes it", async () => {
    await d.click(await d.find('button[aria-label="More actions"]'));
    await d.click(await d.findXPath(`//*[@role="menuitem"][contains(., "Remove")]`));
    await d.click(await d.findXPath(`//*[@role="dialog"]//button[normalize-space(.)="Remove"]`));
    await d.waitFor(() => status("e2e-gui") === null, 10_000, "the CLI to find it gone");
    // Back on the list, without it.
    await d.find('[data-testid="containers-table"]', 5_000);
    await d.waitFor(async () => (await rowStatus("e2e-gui")) === null, 5_000, "its row gone");
  });

  await check("a network the CLI creates appears; connecting from the GUI gives the container an interface", async () => {
    if (!rustlet("network", "create", "e2e-net")) throw new Error("rustlet network create failed");
    await d.go("/networks");
    // A table row isn't "interactable" to WebKitWebDriver; its first cell is.
    await d.click(await d.find('[data-testid="network-row"][data-name="e2e-net"] td', 5_000));
    const id = JSON.parse(rustlet("inspect", "e2e-cli"))[0].id;
    await d.waitFor(() => d.exec(`return !!document.querySelector('select option[value="' + arguments[0] + '"]')`, id), 5_000, "e2e-cli in the connect list");
    await d.select("select", id);
    await d.click(await d.button("Connect"));
    await d.waitFor(
      () => (rustlet("exec", "e2e-cli", "ip", "addr") ?? "").includes("eth1"),
      10_000,
      "eth1 in the container",
    );
    // The graph has the edge too: a label with its new address.
    const ip = JSON.parse(rustlet("network", "inspect", "e2e-net"))[0].containers[0].ip_address.split("/")[0];
    await d.findXPath(`//*[@data-testid="topology"]//*[text()=${JSON.stringify(ip)}]`, 5_000);
  });

  await check("a volume created in the GUI is the CLI's to see", async () => {
    await d.go("/volumes");
    await d.click(await d.button("Create"));
    await d.type(await d.find('[role="dialog"] input'), "e2e-vol");
    await d.click(await d.findXPath(`//*[@role="dialog"]//button[normalize-space(.)="Create"]`));
    await d.waitFor(() => (rustlet("volume", "ls") ?? "").includes("e2e-vol"), 5_000, "e2e-vol in rustlet volume ls");
    await d.find('[data-testid="volume-row"][data-name="e2e-vol"]', 5_000);
  });

  if (process.env.E2E_RESTART) {
    await check("after a daemon restart the app reconnects and follows the CLI again", async () => {
      await d.go("/containers");
      execFileSync("sh", ["-c", process.env.E2E_RESTART], { stdio: "ignore" });
      await d.find('[data-testid="connection"][data-state="connected"]', 20_000);
      // The container outlived the restart, and new events arrive.
      await d.waitFor(async () => (await rowStatus("e2e-cli")) === "running", 10_000, "e2e-cli still running");
      if (rustlet("pause", "e2e-cli") == null) throw new Error("rustlet pause failed");
      await d.waitFor(async () => (await rowStatus("e2e-cli")) === "paused", 5_000, "e2e-cli paused in the list");
    });
  }

  await check("a container removed by the CLI leaves the list", async () => {
    await d.go("/containers");
    await d.waitFor(async () => (await rowStatus("e2e-cli")) != null, 5_000, "e2e-cli in the list");
    if (rustlet("rm", "-f", "e2e-cli") == null) throw new Error("rustlet rm failed");
    await d.waitFor(async () => (await rowStatus("e2e-cli")) === null, 5_000, "e2e-cli gone from the list");
  });

  console.log(`all ${step} steps passed`);
} finally {
  await d.quit();
  for (const n of ["e2e-cli", "e2e-gui"]) rustlet("rm", "-f", n);
  rustlet("network", "rm", "e2e-net");
  rustlet("volume", "rm", "e2e-vol");
}
