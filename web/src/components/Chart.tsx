import { useEffect, useRef } from "react";
import * as echarts from "echarts/core";
import { BarChart, LineChart, MapChart, PieChart } from "echarts/charts";
import { GeoComponent, GridComponent, LegendComponent, TooltipComponent, VisualMapComponent } from "echarts/components";
import { CanvasRenderer } from "echarts/renderers";
import { feature } from "topojson-client";
import type { Topology } from "topojson-specification";
import world from "world-atlas/countries-110m.json";
import { countryName, numericToAlpha2 } from "../lib/format";
import { useTheme } from "../lib/theme";

echarts.use([LineChart, BarChart, PieChart, MapChart, GridComponent, TooltipComponent, LegendComponent, GeoComponent, VisualMapComponent, CanvasRenderer]);

// Register the world map once, keyed by ISO alpha-2 code so it lines up with
// the GeoIP country codes the backend stores.
let mapReady = false;
export function ensureWorldMap() {
  if (mapReady) return;
  const topo = world as unknown as Topology;
  const fc = feature(topo, topo.objects.countries) as unknown as GeoJSON.FeatureCollection;
  fc.features = fc.features.filter((f) => String(f.id) !== "010"); // Antarctica
  for (const f of fc.features) {
    const code = numericToAlpha2(String(f.id ?? ""));
    f.properties = { ...f.properties, name: code || String(f.properties?.name ?? "") };
    fixAntimeridian(f.geometry);
  }
  echarts.registerMap("world", fc as never);
  mapReady = true;
}
export { countryName };

// world-atlas is unprojected; rings that cross ±180° (Russia, Fiji) would be
// drawn as streaks across the whole map. Clamp them onto the near edge.
function fixAntimeridian(g: GeoJSON.Geometry) {
  const rings: GeoJSON.Position[][] =
    g.type === "Polygon" ? g.coordinates : g.type === "MultiPolygon" ? g.coordinates.flat() : [];
  for (const ring of rings) {
    const lons = ring.map((p) => p[0]);
    if (Math.max(...lons) - Math.min(...lons) <= 180) continue;
    const east = lons.filter((l) => l > 0).length >= lons.length / 2;
    for (const p of ring) {
      if (east && p[0] < 0) p[0] = 180;
      if (!east && p[0] > 0) p[0] = -180;
    }
  }
}

export function cssVar(name: string) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

/** Base options shared by every chart, derived from the current theme. */
export function baseOption(): echarts.EChartsCoreOption {
  const muted = cssVar("--muted");
  const border = cssVar("--border");
  return {
    textStyle: { fontFamily: "inherit", color: muted },
    tooltip: {
      backgroundColor: cssVar("--surface"),
      borderColor: border,
      textStyle: { color: cssVar("--fg"), fontSize: 12 },
      extraCssText: "border-radius:10px;box-shadow:0 8px 24px rgba(0,0,0,.18);",
    },
    grid: { left: 8, right: 12, top: 28, bottom: 4, containLabel: true },
  };
}

export function Chart({ option, height = 260, className }: { option: echarts.EChartsCoreOption; height?: number; className?: string }) {
  const ref = useRef<HTMLDivElement>(null);
  const inst = useRef<echarts.ECharts | null>(null);
  const { dark } = useTheme();

  useEffect(() => {
    if (!ref.current) return;
    inst.current = echarts.init(ref.current, undefined, { renderer: "canvas" });
    const ro = new ResizeObserver(() => inst.current?.resize());
    ro.observe(ref.current);
    return () => {
      ro.disconnect();
      inst.current?.dispose();
      inst.current = null;
    };
  }, []);

  useEffect(() => {
    inst.current?.setOption({ ...baseOption(), ...option }, { notMerge: true, lazyUpdate: true });
  }, [option, dark]);

  return <div ref={ref} className={className} style={{ height, width: "100%" }} />;
}
