import { describe, expect, it, vi } from "vitest";
import { validateActionInput } from "../../core/validation.ts";
import { ProviderRequestError } from "../provider-runtime.ts";
import { zerotierActions } from "./actions.ts";
import { credentialValidators, zerotierActionHandlers } from "./executors.ts";
import { createZerotierContext, zerotierV1BaseUrl, zerotierV2BaseUrl } from "./runtime.ts";

const jsonFetcher = (payload: unknown, assert?: (url: string, init?: RequestInit) => void): typeof fetch =>
  vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    assert?.(input.toString(), init);
    return Response.json(payload);
  }) as unknown as typeof fetch;

const v1Context = (fetcher: typeof fetch, values: Record<string, string> = {}) =>
  createZerotierContext({ apiVersion: "v1", apiKey: "v1-key", ...values }, fetcher);

const v2Context = (fetcher: typeof fetch, values: Record<string, string> = {}) =>
  createZerotierContext({ apiVersion: "v2", apiKey: "v2-key", orgId: "org-default", ...values }, fetcher);

describe("ZeroTier auth headers", () => {
  it("uses 'token <key>' for v1 connections", async () => {
    const fetcher = jsonFetcher([], (url, init) => {
      expect(url).toBe(`${zerotierV1BaseUrl}/network`);
      expect(new Headers(init?.headers).get("authorization")).toBe("token v1-key");
    });
    await zerotierActionHandlers.list_networks({}, v1Context(fetcher));
  });

  it("uses 'Bearer <key>' for v2 connections", async () => {
    const fetcher = jsonFetcher([], (url, init) => {
      expect(url).toContain(`${zerotierV2BaseUrl}/network`);
      expect(new Headers(init?.headers).get("authorization")).toBe("Bearer v2-key");
    });
    await zerotierActionHandlers.list_networks({}, v2Context(fetcher));
  });
});

describe("ZeroTier v2 request shaping", () => {
  it("falls back to the connection orgId for list_networks", async () => {
    const fetcher = jsonFetcher([], (url) => {
      expect(url).toBe(`${zerotierV2BaseUrl}/network?org-id=org-default`);
    });
    const result = await zerotierActionHandlers.list_networks({}, v2Context(fetcher));
    expect(result).toEqual({ items: [] });
  });

  it("prefers an explicit orgId over the connection default", async () => {
    const fetcher = jsonFetcher({ items: [] }, (url) => {
      expect(url).toBe(`${zerotierV2BaseUrl}/network?org-id=org-explicit&stats=true`);
    });
    await zerotierActionHandlers.list_networks({ orgId: "org-explicit", stats: true }, v2Context(fetcher));
  });

  it("routes bulk member updates to the member endpoints", async () => {
    const members = [{ deviceId: "a" }, { deviceId: "b" }];
    const fetcher = jsonFetcher(members, (url, init) => {
      expect(url).toBe(`${zerotierV2BaseUrl}/network/nw1/member`);
      expect(init?.method).toBe("POST");
      expect(JSON.parse(String(init?.body))).toEqual(members);
    });
    const result = await zerotierActionHandlers.add_members({ networkId: "nw1", members }, v2Context(fetcher));
    expect(result).toEqual({ items: members });
  });

  it("sends flow rules to the v2beta base URL", async () => {
    const fetcher = jsonFetcher({ rules: [] }, (url) => {
      expect(url).toBe("https://central.zerotier.com/api/v2beta/network/nw1/flow-rule");
    });
    await zerotierActionHandlers.get_flow_rules({ networkId: "nw1" }, v2Context(fetcher));
  });

  it("maps IAM actions to the resource iam endpoint", async () => {
    const fetcher = jsonFetcher({ tuples: [] }, (url) => {
      expect(url).toBe(`${zerotierV2BaseUrl}/network-group/grp1/iam`);
    });
    await zerotierActionHandlers.get_iam({ resourceType: "network-group", resourceId: "grp1" }, v2Context(fetcher));
  });
});

describe("ZeroTier version guards", () => {
  it("rejects v2-only actions on v1 connections", async () => {
    const fetcher = jsonFetcher([]);
    const error = await zerotierActionHandlers.list_orgs({}, v1Context(fetcher)).catch((err: unknown) => err);
    expect(error).toBeInstanceOf(ProviderRequestError);
    expect((error as ProviderRequestError).status).toBe(400);
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("rejects v1-only actions on v2 connections", async () => {
    const fetcher = jsonFetcher({});
    const error = await zerotierActionHandlers.get_status({}, v2Context(fetcher)).catch((err: unknown) => err);
    expect(error).toBeInstanceOf(ProviderRequestError);
    expect((error as ProviderRequestError).status).toBe(400);
  });

  it("rejects an invalid apiVersion before any request", () => {
    expect(() => createZerotierContext({ apiVersion: "v3", apiKey: "key" }, jsonFetcher({}))).toThrow(
      ProviderRequestError,
    );
  });
});

describe("ZeroTier list normalization", () => {
  it("wraps bare payloads as a single item", async () => {
    const fetcher = jsonFetcher({ id: "nw1" });
    const result = await zerotierActionHandlers.list_networks({}, v1Context(fetcher));
    expect(result).toEqual({ items: [{ id: "nw1" }] });
  });

  it("returns an empty list for null payloads", async () => {
    const fetcher = vi.fn(async () => new Response(null, { status: 204 })) as unknown as typeof fetch;
    const result = await zerotierActionHandlers.list_networks({}, v1Context(fetcher));
    expect(result).toEqual({ items: [] });
  });
});

describe("ZeroTier error propagation", () => {
  it("surfaces upstream error payloads as ProviderRequestError", async () => {
    const fetcher = vi.fn(async () =>
      Response.json({ message: "bad request" }, { status: 400, statusText: "Bad Request" }),
    ) as unknown as typeof fetch;
    const error = await zerotierActionHandlers.list_networks({}, v1Context(fetcher)).catch((err: unknown) => err);
    expect(error).toBeInstanceOf(ProviderRequestError);
    expect((error as ProviderRequestError).status).toBe(400);
  });
});

describe("ZeroTier credential validation", () => {
  it("validates v1 credentials via GET /status and identifies the token user", async () => {
    const status = { type: "CentralStatus", clock: 1, user: { id: "user-1", displayName: "Joe User" } };
    const fetcher = jsonFetcher(status, (url, init) => {
      expect(url).toBe(`${zerotierV1BaseUrl}/status`);
      expect(new Headers(init?.headers).get("authorization")).toBe("token v1-key");
    });
    const result = await credentialValidators.customCredential!(
      { values: { apiVersion: "v1", apiKey: "v1-key" } },
      { fetcher },
    );
    expect(result?.profile).toEqual({ accountId: "user-1", displayName: "Joe User" });
    expect(result?.metadata?.apiBaseUrl).toBe(zerotierV1BaseUrl);
  });

  it("rejects v1 credentials whose status carries no user", async () => {
    const fetcher = jsonFetcher({ type: "CentralStatus", clock: 1, user: null });
    const error = await credentialValidators.customCredential!(
      { values: { apiVersion: "v1", apiKey: "bad-key" } },
      { fetcher },
    ).catch((err: unknown) => err);
    expect(error).toBeInstanceOf(ProviderRequestError);
    expect((error as ProviderRequestError).status).toBe(401);
  });

  it("validates v2 credentials via GET /org and identifies the service account organization", async () => {
    const fetcher = jsonFetcher({ items: [{ id: "org1", name: "Acme Org" }] }, (url, init) => {
      expect(url).toBe(`${zerotierV2BaseUrl}/org`);
      expect(new Headers(init?.headers).get("authorization")).toBe("Bearer v2-key");
    });
    const result = await credentialValidators.customCredential!(
      { values: { apiVersion: "v2", apiKey: "v2-key" } },
      { fetcher },
    );
    expect(result?.profile).toEqual({ accountId: "org1", displayName: "Acme Org" });
    expect(result?.metadata?.apiBaseUrl).toBe(zerotierV2BaseUrl);
  });

  it("uses the configured orgId to pick among several v2 organizations", async () => {
    const orgs = {
      items: [
        { id: "org1", name: "Acme Org" },
        { id: "org2", name: "Beta Org" },
      ],
    };
    const result = await credentialValidators.customCredential!(
      { values: { apiVersion: "v2", apiKey: "v2-key", orgId: "org2" } },
      { fetcher: jsonFetcher(orgs) },
    );
    expect(result?.profile).toEqual({ accountId: "org2", displayName: "Beta Org" });
  });

  it("leaves the v2 account id to the runtime default when no single organization is identified", async () => {
    const orgs = {
      items: [
        { id: "org1", name: "Acme Org" },
        { id: "org2", name: "Beta Org" },
      ],
    };
    const result = await credentialValidators.customCredential!(
      { values: { apiVersion: "v2", apiKey: "v2-key" } },
      { fetcher: jsonFetcher(orgs) },
    );
    expect(result?.profile).toEqual({ accountId: undefined, displayName: "ZeroTier New Central v2" });
  });
});

describe("ZeroTier action schemas", () => {
  const action = (name: string) => zerotierActions.find((candidate) => candidate.name === name)!;

  it("treats check_permissions as a read and accepts the v2 resource types", () => {
    const checkPermissions = action("check_permissions");
    const check = (resourceType: string) => ({ checks: [{ permission: "read", resourceType, resourceId: "r1" }] });

    expect(checkPermissions.operationType).toBe("read");
    expect(validateActionInput(checkPermissions, check("network_group")).valid).toBe(true);
    expect(validateActionInput(checkPermissions, check("networkGroup")).valid).toBe(false);
  });
});
