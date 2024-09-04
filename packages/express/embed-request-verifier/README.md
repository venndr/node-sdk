# Embed signature verifier for Express

This middleware verifies signatures in app embed requests coming from Venndr.

## Installation

```
npm install --save @venndr/express-embed-request-verifier
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
import { keyFetcher } from "@venndr/express-public-key-fetcher";
import { verifyEmbedRequest } from "@venndr/embed-request-verifier";

const app = express();

const embedVerifier = verifyEmbedRequest(keyFetcher);

app.get("/embed", embedVerifier, (_, r) => {
	console.log("received valid embed request");

	r.send("Hello world!");
});

app.listen(process.env.PORT ?? 8080);
```

### Development mode

To skip the signature verification the `UNSAFE_SKIP_EMBED_VERIFY` environment variable can be set to any non-empty value. This should only be used during development and never in production.
