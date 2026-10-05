// Which containers the lists show. A build runs each RUN step in a
// container of its own, labelled `io.rustlet.build` with the build's id and
// removed after the step: real containers, which `rustlet ps -a` lists as
// Docker's classic builder's are listed, but noise among the user's own,
// coming and going by the second during a build. So the lists hide them
// unless asked to show them.

import type { ContainerSummary, Info } from "@/bindings";

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

/** The container counts of the daemon's `Info` (every container, by state)
 * less the build containers of `list` (all the containers): the numbers
 * the lists show, which leave those out. */
export function countsLessBuilds<T extends Pick<Info, "containers" | "running" | "paused" | "stopped">>(
  info: T,
  list: Pick<ContainerSummary, "labels" | "state">[],
): T {
  const counts = { containers: info.containers, running: info.running, paused: info.paused, stopped: info.stopped };
  for (const c of list) {
    if (!isBuildContainer(c)) continue;
    counts.containers--;
    // As the daemon counts: what isn't running or paused is stopped.
    if (c.state.status === "running") counts.running--;
    else if (c.state.status === "paused") counts.paused--;
    else counts.stopped--;
  }
  return { ...info, ...counts };
}
