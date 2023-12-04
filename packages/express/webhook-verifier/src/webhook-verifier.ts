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
        const message = Buffer.concat([
          Buffer.from(messageHeaders.reduce((acc, header) => acc + req.header(header), "")),
          body,
        ]);

        if (!crypto.verify("sha256", message, key, signature)) {
          next(new Error("invalid webhook: signature validation failed"));
          return;
        }

        req.body = JSON.parse(body.toString());

        next();
      })
      .catch(next);
  };

type Fetch = typeof fetch;

export interface KeyCache<
  KT extends string = string,
  VT extends crypto.KeyObject = crypto.KeyObject,
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
              return Promise.reject(new Error(`error fetching key: ${r.status}`));
            }

            if (!r.body) {
              return Promise.reject(new Error("error fetching key: empty response"));
            }

            const keyBytes = await r.arrayBuffer();
            const key = crypto.createPublicKey(Buffer.from(keyBytes));

            keyCache.set(version, key);

            return key;
          }),
      ),
    );
};
