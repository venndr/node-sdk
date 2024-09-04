/*
 * This middleware verifies a Venndr Webhook request and parses the valid payload into JSON
 * overwriting the `request.body` property.
 *
 * It expects the incoming request's body to have been slurped, which is most easily accomplished
 * by preceding this middleware with the `express.raw()` middleware.
 */

// this line is required, because `fetch` is not yet in `@types/node`. it is still in experimental
// state, but it's stable enough for our purposes.
/// <reference lib="dom" />

import * as crypto from "crypto";
import { KeyFetcher } from "@venndr/public-key-fetcher";
import { Request as ExRequest, Response as ExResponse, NextFunction } from "express";

const messageHeaders = [
  "venndr-id",
  "venndr-key-version",
  "venndr-version",
  "venndr-timestamp",
  "venndr-platform-id",
  "venndr-store-id",
  "venndr-topic",
];

export const verifyWebhookSignature =
  (fetchKey: KeyFetcher) => (req: ExRequest, _: ExResponse, next: NextFunction) => {
    if (!Buffer.isBuffer(req.body)) {
      throw new Error("expected request.body to be a Buffer");
    }

    if (process.env.UNSAFE_SKIP_WEBHOOK_VERIFY != null) {
      req.body = JSON.parse((req.body as Buffer).toString());
      next();
      return;
    }

    if (!req.is("application/json")) {
      next(
        new Error(`invalid webhook: expected application/json, got: ${req.header("content-type")}`),
      );
      return;
    }

    const keyVersion = req.header("venndr-key-version");

    if (!keyVersion) {
      next(new Error("invalid webhook: missing venndr-key-version"));
      return;
    }

    const body = req.body as Buffer;

    if (!body || body.length == 0) {
      next(new Error("invalid webhook: empty payload"));
      return;
    }

    fetchKey(keyVersion)
      .then((key) => {
        const signature = Buffer.from(req.header("venndr-signature") ?? "", "base64");
        const message = Buffer.concat(
          messageHeaders.map((h) => Buffer.from(String(req.header(h)))).concat([body]),
        );

        if (!crypto.verify("sha256", message, key, signature)) {
          next(new Error("invalid webhook: signature validation failed"));
          return;
        }

        req.body = JSON.parse(body.toString());

        next();
      })
      .catch(next);
  };
