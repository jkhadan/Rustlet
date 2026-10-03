import "./index.css";

import { focusManager, QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { HashRouter } from "react-router";
import { Toaster } from "sonner";

import { App } from "./App";
import { TooltipProvider } from "./components/ui/tooltip";
import { DaemonProvider } from "./lib/daemon";
import { CommandFailed } from "./lib/ipc";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // Events keep the cache current (lib/events.ts); a refetch on focus is
      // a cheap second chance.
      staleTime: 5_000,
      // Retrying can't help when the daemon refused or isn't there.
      retry: (failures, error) => failures < 1 && !(error instanceof CommandFailed && error.kind !== "failed"),
    },
  },
});

// TanStack Query takes only a `visibilitychange` for focus, and a desktop
// window behind another stays visible: coming back to the app from a
// terminal is a window `focus`, so that counts too.
focusManager.setEventListener((onFocus) => {
  const listener = () => onFocus();
  window.addEventListener("visibilitychange", listener);
  window.addEventListener("focus", listener);
  return () => {
    window.removeEventListener("visibilitychange", listener);
    window.removeEventListener("focus", listener);
  };
});

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <DaemonProvider>
        <TooltipProvider delayDuration={300}>
          <HashRouter>
            <App />
          </HashRouter>
          <Toaster position="bottom-right" richColors closeButton theme="system" />
        </TooltipProvider>
      </DaemonProvider>
    </QueryClientProvider>
  </StrictMode>,
);
