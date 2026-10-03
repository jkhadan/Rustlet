// A small time-series chart: uPlot draws on a canvas, so a chart of 120
// points redrawn every second costs next to nothing.

import "uplot/dist/uPlot.min.css";

import { useEffect, useRef } from "react";
import uPlot from "uplot";

export interface ChartSeries {
  label: string;
  color: string;
}

export function Chart({
  data,
  series,
  format,
  height = 140,
  min,
  max,
}: {
  /** `[x (unix seconds), ...one column per series]`. */
  data: number[][];
  series: ChartSeries[];
  format: (v: number) => string;
  height?: number;
  min?: number;
  max?: number;
}) {
  const host = useRef<HTMLDivElement>(null);
  const plot = useRef<uPlot | null>(null);
  const fmt = useRef(format);
  fmt.current = format;

  // Made once per set of series; data updates go through setData.
  const key = series.map((s) => s.label + s.color).join("|");
  useEffect(() => {
    if (!host.current) return;
    const axis = {
      stroke: "#8b8b94",
      grid: { stroke: "rgba(128,128,128,0.14)", width: 1 },
      ticks: { stroke: "rgba(128,128,128,0.2)", width: 1 },
      font: "11px Inter, system-ui, sans-serif",
    };
    const opts: uPlot.Options = {
      width: host.current.clientWidth,
      height,
      legend: { show: false },
      cursor: { drag: { x: false, y: false }, points: { size: 6 } },
      scales: {
        x: { time: true },
        y: { range: (_u, lo, hi) => [min ?? Math.min(0, lo), Math.max(max ?? 0, hi * 1.1 || 1)] },
      },
      axes: [
        { ...axis, space: 60 },
        { ...axis, size: 64, values: (_u, vals) => vals.map((v) => fmt.current(v)) },
      ],
      series: [
        {},
        ...series.map((s) => ({
          label: s.label,
          stroke: s.color,
          width: 1.5,
          fill: `${s.color}22`,
          points: { show: false },
        })),
      ],
    };
    const u = new uPlot(opts, data as uPlot.AlignedData, host.current);
    plot.current = u;
    const observer = new ResizeObserver(() => {
      if (host.current) u.setSize({ width: host.current.clientWidth, height });
    });
    observer.observe(host.current);
    return () => {
      observer.disconnect();
      u.destroy();
      plot.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, height, min, max]);

  useEffect(() => {
    plot.current?.setData(data as uPlot.AlignedData);
  }, [data]);

  return <div ref={host} className="w-full" />;
}
