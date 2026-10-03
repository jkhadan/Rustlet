import { describe, expect, it } from "vitest";

import type { ContainerState } from "@/bindings";

import { bytes, commandText, duration, imageName, portsText, splitCommand, statusText } from "./format";

describe("format", () => {
  it("bytes in binary units", () => {
    expect(bytes(0)).toBe("0 B");
    expect(bytes(1536)).toBe("1.5 KiB");
    expect(bytes(7.8 * 1024 ** 3)).toBe("7.8 GiB");
    expect(bytes(null)).toBe("–");
  });

  it("durations as Docker says them", () => {
    expect(duration(0.2)).toBe("Less than a second");
    expect(duration(42)).toBe("42 seconds");
    expect(duration(70)).toBe("About a minute");
    expect(duration(3 * 3600)).toBe("3 hours");
    expect(duration(3 * 86400)).toBe("3 days");
  });

  it("status like rustlet ps", () => {
    const now = Date.parse("2026-10-02T12:10:00Z");
    const st = (s: Partial<ContainerState>): ContainerState => ({
      status: "running",
      pid: null,
      exit_code: null,
      oom_killed: false,
      error: null,
      started_at: null,
      finished_at: null,
      restart_count: 0,
      ...s,
    });
    expect(statusText(st({ started_at: "2026-10-02T12:05:00.123456789Z" }), now)).toBe("Up 5 minutes");
    expect(statusText(st({ status: "exited", exit_code: 137, finished_at: "2026-10-02T10:10:00Z" }), now)).toBe(
      "Exited (137) 2 hours ago",
    );
    expect(statusText(st({ status: "created" }), now)).toBe("Created");
  });

  it("ports collapse the IPv4 and IPv6 bindings of one port", () => {
    expect(
      portsText([
        { host_ip: "0.0.0.0", host_port: 8080, container_port: 80, protocol: "tcp" },
        { host_ip: "::", host_port: 8080, container_port: 80, protocol: "tcp" },
        { host_ip: "127.0.0.1", host_port: 5353, container_port: 53, protocol: "udp" },
      ]),
    ).toEqual(["8080->80/tcp", "127.0.0.1:5353->53/udp"]);
  });

  it("commands split and print like a shell's", () => {
    expect(splitCommand(`sh -c "echo 'hi there'; sleep 1"`)).toEqual(["sh", "-c", "echo 'hi there'; sleep 1"]);
    expect(splitCommand(`a\\ b '' c`)).toEqual(["a b", "", "c"]);
    // In double quotes a backslash stays, but before $ ` " \ and a newline.
    expect(splitCommand(String.raw`sh -c "printf 'a\nb'"`)).toEqual(["sh", "-c", String.raw`printf 'a\nb'`]);
    expect(splitCommand('echo "\\$HOME \\` \\" \\\\ \\x"')).toEqual(["echo", '$HOME ` " \\ \\x']);
    expect(splitCommand('echo "a\\\nb"')).toEqual(["echo", "ab"]);
    expect(() => splitCommand(`echo "x`)).toThrow();
    expect(commandText(["sh", "-c", "echo hi"])).toBe("sh -c 'echo hi'");
    expect(imageName("docker.io/library/alpine:latest")).toBe("alpine:latest");
    expect(imageName("ghcr.io/o/n:1")).toBe("ghcr.io/o/n:1");
  });
});
