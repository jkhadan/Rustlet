import { describe, expect, it } from "vitest";

import { BUILD_LABEL, hideBuildContainers, isBuildContainer } from "./containers";

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
