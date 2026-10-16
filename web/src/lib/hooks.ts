import { useCallback, useEffect, useState } from "react";
import { api, type Site } from "./api";

/** Loads data once and on demand; errors are kept for display. */
export function useLoad<T>(fn: () => Promise<T>, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string>("");
  const [loading, setLoading] = useState(true);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const load = useCallback(fn, deps);
  const reload = useCallback(async () => {
    setLoading(true);
    try {
      setData(await load());
      setError("");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, [load]);
  useEffect(() => {
    reload();
  }, [reload]);
  return { data, error, loading, reload, setData };
}

export function useSites() {
  const { data, reload } = useLoad(() => api.sites().then((r) => r.sites));
  const sites = data ?? [];
  const name = (id: number) => (id === 0 ? "全局" : sites.find((s: Site) => s.id === id)?.name ?? `#${id}`);
  return { sites, name, reload };
}
