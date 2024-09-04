# Caching public key downloader for the Venndr Node SDK

This library is a basic version of the key fetcher used by utilities in the Venndr Node SDK.

For most cases the defaults should be all you need, but for more advanced usage the fetcher's initialiser optionally takes a configuration object. See `KeyFetcherOptions` below.

### Fetch API

The fetcher uses the [Fetch API](https://nodejs.org/dist/latest-v20.x/docs/api/globals.html#fetch) to download keys. If for any reason you wish to provide your own agent, any compatible implementation can be passed as an option to the initialiser.

### Caching

Caching the keys is strongly recommended for production deployments to avoid repeatedly fetching identical data.

By default, the bundled key fetcher uses an in-memory `Map` to store successfully fetched keys. Should you want something more robust, the cache implementation is pluggable and can be passed as an option to the initialiser. The cache implementation should match the `KeyCache` interface, which you can find below.

### TypeScript types for the key fetcher

```typescript
// KeyFetcher is what the utilities in the Node SDK expect to receive.
type KeyFetcher = (version: string) => Promise<crypto.KeyObject>;

// KeyCache<KT, VT> is the cache interface for the key fetcher
interface KeyCache<KT extends string = string, VT extends crypto.KeyObject = crypto.KeyObject> {
  get(k: KT): Promise<VT | null | undefined> | VT | null | undefined;
  set(k: KT, v: VT): void;
}

// KeyFetcherOptions is pluggable functionality for the key fetcher
interface KeyFetcherOptions {
  baseURL?: string; // base URL for fetching public keys
  cache?: KeyCache; // any compatible cache implementation, see KeyCache<KT, VT>
  fetch?: Fetch;    // any Fetch API compatible agent
}
```