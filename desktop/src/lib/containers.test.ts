import { describe, expect, it } from "vitest";

import { BUILD_LABEL, countsLessBuilds, hideBuildContainers, isBuildContainer } from "./containers";

const web = { name: "web", labels: { "io.rustlet.compose.service": "web" } };
const step = { name: "eager_turing", labels: { [BUILD_LABEL]: "0123456789ab" } };

describe("build containers", () => {
  it("are told by their label, whatever its value", () => {
    expect(isBuildContainer(step)).toBe(true);
    expect(isBuildContainer({ labels: { [BUILD_LABEL]: "" } })).toBe(true);
    expect(isBuildContainer(web)).toBe(false);
    expect(isBuildContainer({ labels: {} })).toBe(false);
  });

  it("are left out of a list unless asked for, and counted", () => {
    expect(hideBuildContainers([web, step, step], false)).toEqual({ shown: [web], hidden: 2 });
    expect(hideBuildContainers([web, step], true)).toEqual({ shown: [web, step], hidden: 0 });
    expect(hideBuildContainers([web], false)).toEqual({ shown: [web], hidden: 0 });
  });
});

describe("the daemon's counts", () => {
  const counts = { containers: 5, running: 3, paused: 1, stopped: 1, images: 2 };
  const state = (status: string) => ({ status }) as never;

  it("lose the build containers, each from the count of its state", () => {
    const list = [
      { ...web, state: state("running") },
      { ...step, state: state("running") },
      { ...step, state: state("paused") },
      { ...step, state: state("exited") },
    ];
    expect(countsLessBuilds(counts, list)).toEqual({ containers: 2, running: 2, paused: 0, stopped: 0, images: 2 });
  });

  it("stay as they are without a build container", () => {
    expect(countsLessBuilds(counts, [{ ...web, state: state("running") }])).toEqual(counts);
    expect(countsLessBuilds(counts, [])).toEqual(counts);
  });
});
