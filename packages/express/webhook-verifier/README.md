# Webhook signature verifier middleware for Express

Use this middleware to [verify webhook payloads](https://developer.musicglue.com/webhooks/validation.html) against their signature, before handing over control to your handler.

## Installation

```
npm install --save @venndr/express-webhook-verifier
```

## Usage

**Important!** This middleware _must_ be preceded by the [`express.raw()`](https://expressjs.com/en/api.html#express.raw), or an equivalent, middleware. Our recommendation is to not install a global body decoder and only decode payloads for those handlers that expect one.

On successful verification the parsed payload is assigned to `request.body`. On failed verification `request.body` is set to `null` and an error will be passed to `next()`.

### Example

```typescript
import express from "express";
import { keyFetcher, verifyWebhookSignature } from "@venndr/express-webhook-verifier";

const app = express();

const slurpBody = express.raw({ type: "application/json" });
const checkSignature = verifyWebhookSignature(keyFetcher());
const verifyPayload = [slurpBody, checkSignature];

app.post("/webhooks", ...verifyPayload, (req, res) => {
  console.log(`received valid webhook with payload ${req.body}`);

  res.sendStatus(202);
});

app.listen(process.env.PORT ?? "8080")
```

### Development mode

To skip the signature verification the `UNSAFE_SKIP_WEBHOOK_VERIFY` environment variable can be set to any non-empty value. This should only be used during development and never in production.

## The key fetcher

The middleware requires a key fetcher – a function that receives the key version as argument and should return a `Promise<crypto.KeyObject>`.

A key fetcher that satisfies basic use is bundled with this middleware.

For most cases the defaults should be all you need, but for advanced usage the fetcher's initialiser optionally takes a configuration object. See `KeyFetcherOptions` below.

### Fetch API

The bundled fetcher uses the [Fetch API](https://nodejs.org/dist/latest-v20.x/docs/api/globals.html#fetch) to download keys. If for any reason you wish to provide your own agent, any compatible implementation can be passed as an option to the initialiser.

### Caching

Caching the keys is strongly recommended for production deployments to avoid repeatedly fetching identical data.

By default, the bundled key fetcher uses an in-memory `Map` to store successfully fetched keys. Should you want something more robust, the cache implementation is pluggable and can be passed as an option to the initialiser. The cache implementation should match the `KeyCache` interface, which you can find below.

### TypeScript types for the key fetcher

```typescript
// KeyFetcher is what the middleware initialiser expects
type KeyFetcher = (version: string) => Promise<crypto.KeyObject>;

// KeyCache<KT, VT> is the cache interface for the bundled key fetcher
interface KeyCache<KT extends string = string, VT extends crypto.KeyObject = crypto.KeyObject> {
  get(k: KT): Promise<VT | null | undefined> | VT | null | undefined;
  set(k: KT, v: VT): void;
}

// KeyFetcherOptions is pluggable functionality for the bundled key fetcher
interface KeyFetcherOptions {
  baseURL?: string; // base URL for fetching public keys
  cache?: KeyCache; // any compatible cache implementation, see KeyCache<KT, VT>
  fetch?: Fetch;    // any Fetch API compatible agent
}
```
