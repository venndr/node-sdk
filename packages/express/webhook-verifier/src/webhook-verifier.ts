/*
 * This middleware verifies a Venndr Webhook request and parses the valid payload into JSON
 * overwriting the `request.body` property.
 *
 * It expects the incoming request's body to have been slurped, which is most easily accomplished
 * by preceding this middleware with the `express.raw()` middleware.
 */

import * as crypto from "crypto";
import { KeyFetcher } from "@venndr/public-key-fetcher";
import { Request as ExRequest, Response as ExResponse, NextFunction } from "express";

if (process.env.UNSAFE_SKIP_WEBHOOK_VERIFY != null) {
  console.warn("UNSAFE_SKIP_WEBHOOK_VERIFY is set, webhook verification is not enforced");
}

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
      return next();
    }

    if (!req.is("application/json")) {
      return next(
        new Error(`invalid webhook: expected application/json, got: ${req.header("content-type")}`),
      );
    }

    const keyVersion = req.header("venndr-key-version");

    if (!keyVersion) {
      return next(new Error("invalid webhook: missing venndr-key-version"));
    }

    const body = req.body as Buffer;

    if (!body || body.length == 0) {
      return next(new Error("invalid webhook: empty payload"));
    }

    fetchKey(keyVersion)
      .then((key) => {
        const signature = Buffer.from(req.header("venndr-signature") ?? "", "base64");
        const headers = messageHeaders.map<Buffer>((h) => Buffer.from(String(req.header(h))));
        const message = Buffer.concat(headers.concat([body]));

        if (!crypto.verify("sha256", message, key, signature)) {
          next(new Error("invalid webhook: signature validation failed"));
          return;
        }

        req.body = JSON.parse(body.toString());

        next();
      })
      .catch(next);
  };
