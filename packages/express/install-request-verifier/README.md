# Install payload verifier for Express

This middleware verifies signatures in app install requests coming from Venndr.

## Installation

```
npm install --save @venndr/install-request-verifier
```

## The key fetcher

This middleware requires a key fetcher – a function that receives the key version as argument and should return a `Promise<crypto.KeyObject>`.

A key fetcher that satisfies basic use cases is available in the Venndr Node SDK. See [@venndr/public-key-fetcher](https://www.npmjs.com/package/@venndr/public-key-fetcher) for more detailed information.

## Configuration

The middleware has a configurable threshold for signature max age. The default value is 600 seconds.

To set your own limit, pass a configuration object to the middleware initialiser.

```typescript
interface VerifierOptions {
  maxAge?: number; // max signature age in seconds
}
```

## Usage

```typescript
import express from "express";
import { keyFetcher } from "@venndr/public-key-fetcher";
import { verifyInstallRequest } from "@venndr/install-request-verifier";

const app = express();

const slurpBody = express.raw({ type: "application/json" });
const checkSignature = verifyInstallRequest(keyFetcher());
const verifyPayload = [slurpBody, checkSignature];

app.post("/install", installVerifier, (_, r) => {
  console.log("received valid install request");

  r.send("Hello, world!");
});

app.delete("/install", installVerifier, (_, r) => {
  console.log("received valid uninstall request");

  r.send("Goodbye, world!");
});

app.listen(process.env.PORT ?? 8080);
```

### Development mode

To skip the signature verification the `UNSAFE_SKIP_INSTALL_VERIFY` environment variable can be set to any non-empty value. This should only be used during development and never in production.
