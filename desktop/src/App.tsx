import { Route, Routes } from "react-router";

import { Sidebar } from "./components/Sidebar";
import { BuildPage } from "./views/build/BuildPage";
import { ContainerPage } from "./views/containers/ContainerPage";
import { ContainersPage } from "./views/containers/ContainersPage";
import { Dashboard } from "./views/Dashboard";
import { ImagePage } from "./views/images/ImagePage";
import { ImagesPage } from "./views/images/ImagesPage";
import { NetworksPage } from "./views/networks/NetworksPage";
import { StacksPage } from "./views/stacks/StacksPage";
import { VolumesPage } from "./views/VolumesPage";

export function App() {
  return (
    <div className="flex h-full">
      <Sidebar />
      <main className="min-w-0 flex-1 overflow-y-auto">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/containers" element={<ContainersPage />} />
          <Route path="/containers/:id/:tab?" element={<ContainerPage />} />
          <Route path="/stacks" element={<StacksPage />} />
          <Route path="/images" element={<ImagesPage />} />
          <Route path="/images/:ref" element={<ImagePage />} />
          <Route path="/build" element={<BuildPage />} />
          <Route path="/networks" element={<NetworksPage />} />
          <Route path="/volumes" element={<VolumesPage />} />
        </Routes>
      </main>
    </div>
  );
}
