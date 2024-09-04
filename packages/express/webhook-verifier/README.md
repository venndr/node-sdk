# Webhook signature verifier middleware for Express

Use this middleware to [verify webhook payloads](https://developer.musicglue.com/webhooks/validation.html) against their signature, before handing over control to your handler.

## Installation

```
npm install --save @venndr/express-webhook-verifier
```

## The key fetcher

This middleware requires a key fetcher – a function that receives the key version as argument and should return a `Promise<crypto.KeyObject>`.

A key fetcher that satisfies basic use cases is available in the Venndr Node SDK. See [@venndr/public-key-fetcher](https://www.npmjs.com/package/@venndr/public-key-fetcher) for more detailed information.

## Usage

**Important!** This middleware _must_ be preceded by the [`express.raw()`](https://expressjs.com/en/api.html#express.raw), or an equivalent, middleware. Our recommendation is to not install a global body decoder and only decode payloads for those handlers that expect one.

On successful verification the parsed payload is assigned to `request.body`. On failed verification `request.body` is set to `null` and an error will be passed to `next()`.

### Example

```typescript
import express from "express";
import { keyFetcher } from "@venndr/public-key-fetcher";
import { verifyWebhookSignature } from "@venndr/express-webhook-verifier";

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
