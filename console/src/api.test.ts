import { afterEach, describe, expect, it, vi } from "vitest";
import { api, ApiError, can, setCsrf, type Me } from "./api";

afterEach(() => vi.unstubAllGlobals());

describe("api client", () => {
  it("sends the CSRF token on writes, not on reads", async () => {
    const calls: Headers[] = [];
    vi.stubGlobal("fetch", async (_: string, init: RequestInit) => {
      calls.push(new Headers(init.headers));
      return new Response("{}", { status: 200 });
    });
    setCsrf("tok123");
    await api("/api/overview");
    await api("/api/settings", { method: "PUT", body: "{}" });
    expect(calls[0].get("X-CSRF-Token")).toBeNull();
    expect(calls[1].get("X-CSRF-Token")).toBe("tok123");
  });

  it("raises ApiError with the server's message", async () => {
    vi.stubGlobal("fetch", async () => new Response(JSON.stringify({ error: "requires the admin role" }), { status: 403 }));
    await expect(api("/api/audit")).rejects.toEqual(new ApiError(403, "requires the admin role"));
  });

  it("ranks roles", () => {
    const me = { role: "operator" } as Me;
    expect(can(me, "viewer")).toBe(true);
    expect(can(me, "operator")).toBe(true);
    expect(can(me, "admin")).toBe(false);
  });
});
