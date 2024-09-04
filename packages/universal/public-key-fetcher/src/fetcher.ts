import crypto from "crypto";

type Fetch = typeof fetch;

export interface KeyCache<
  KT extends string = string,
  VT extends crypto.KeyObject = crypto.KeyObject
> {
  get(k: KT): Promise<VT | null | undefined> | VT | null | undefined;
  set(k: KT, v: VT): void;
}

export type KeyFetcher = (version: string) => Promise<crypto.KeyObject>;

export interface KeyFetcherOptions {
  baseURL?: string;
  cache?: KeyCache;
  fetch?: Fetch;
}

const keysBaseURL = "https://api.venndr.cloud/.well-known/public-keys";

export const keyFetcher = (options: KeyFetcherOptions = {}): KeyFetcher => {
  const fetch = options?.fetch ?? global.fetch;
  const keyCache = options?.cache ?? new Map<string, crypto.KeyObject>();
  const normalBaseURL = (options?.baseURL ?? keysBaseURL).replace(/\/$/, "");

  return (version: string) =>
    new Promise(async (res) =>
      res(
        (await keyCache.get(version)) ??
          fetch(`${normalBaseURL}/${version}`).then(async (r) => {
            if (!r.ok) {
              return Promise.reject(
                new Error(`error fetching key: ${r.status}`)
              );
            }

            if (!r.body) {
              return Promise.reject(
                new Error("error fetching key: empty response")
              );
            }

            const keyBytes = await r.arrayBuffer();
            const key = crypto.createPublicKey(Buffer.from(keyBytes));

            keyCache.set(version, key);

            return key;
          })
      )
    );
};
