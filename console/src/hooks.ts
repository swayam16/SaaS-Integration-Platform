import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "./api";

/** Fetch JSON, optionally refreshing on an interval while the tab is visible. */
export function useData<T>(path: string, refreshMs = 0) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const alive = useRef(true);

  const load = useCallback(async () => {
    try {
      const d = await api<T>(path);
      if (alive.current) {
        setData(d);
        setError(null);
      }
    } catch (e) {
      if (alive.current) setError((e as Error).message);
    }
  }, [path]);

  useEffect(() => {
    alive.current = true;
    load();
    if (!refreshMs) return () => void (alive.current = false);
    const id = window.setInterval(() => {
      if (document.visibilityState === "visible") load();
    }, refreshMs);
    return () => {
      alive.current = false;
      window.clearInterval(id);
    };
  }, [load, refreshMs]);

  return { data, error, reload: load };
}

export function useHashRoute(): [string, URLSearchParams] {
  const read = () => {
    const raw = window.location.hash.replace(/^#/, "") || "/overview";
    const [path, query = ""] = raw.split("?");
    return [path, new URLSearchParams(query)] as [string, URLSearchParams];
  };
  const [route, setRoute] = useState(read);
  useEffect(() => {
    const on = () => setRoute(read());
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  return route;
}
