// Which containers the lists show. A build runs each RUN step in a
// container of its own, labelled `io.rustlet.build` with the build's id and
// removed after the step: real containers, which `rustlet ps -a` lists as
// Docker's classic builder's are listed, but noise among the user's own,
// coming and going by the second during a build. So the lists hide them
// unless asked to show them.

import type { ContainerSummary } from "@/bindings";

/** The label on a build's step containers (rustletd's `BUILD_LABEL`). */
export const BUILD_LABEL = "io.rustlet.build";

export function isBuildContainer(c: Pick<ContainerSummary, "labels">): boolean {
  return c.labels != null && Object.hasOwn(c.labels, BUILD_LABEL);
}

/** `list` less its build containers, unless `show`; and how many were
 * left out. */
export function hideBuildContainers<T extends Pick<ContainerSummary, "labels">>(
  list: T[],
  show: boolean,
): { shown: T[]; hidden: number } {
  if (show) return { shown: list, hidden: 0 };
  const shown = list.filter((c) => !isBuildContainer(c));
  return { shown, hidden: list.length - shown.length };
}
