// Every piece of daemon state a view shows, as a TanStack Query. The keys
// are lib/events.ts's, which is how daemon events reach them.

import { useQuery } from "@tanstack/react-query";

import { keys } from "./events";
import { api } from "./ipc";

export const useContainers = (all = true) =>
  useQuery({ queryKey: keys.containers(all), queryFn: () => api.containers.list(all) });

export const useContainer = (id: string) =>
  useQuery({ queryKey: keys.container(id), queryFn: () => api.containers.inspect(id) });

export const useIsolation = (id: string, enabled: boolean) =>
  useQuery({ queryKey: keys.isolation(id), queryFn: () => api.containers.isolation(id), enabled });

export const useImages = () => useQuery({ queryKey: keys.images(), queryFn: api.images.list });

export const useImage = (name: string) =>
  useQuery({ queryKey: keys.image(name), queryFn: () => api.images.inspect(name) });

export const useNetworks = () => useQuery({ queryKey: keys.networks(), queryFn: api.networks.list });

export const useVolumes = () => useQuery({ queryKey: keys.volumes(), queryFn: api.volumes.list });

export const useInfo = () => useQuery({ queryKey: keys.info(), queryFn: api.daemon.info });

export const useStacks = () => useQuery({ queryKey: keys.stacks(), queryFn: api.compose.stacks });
