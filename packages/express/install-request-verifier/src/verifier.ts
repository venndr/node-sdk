import * as crypto from "crypto";
import { KeyFetcher } from "@venndr/public-key-fetcher";
import { Request as ExRequest, NextFunction } from "express";

if (process.env.UNSAFE_SKIP_INSTALL_VERIFY != null) {
  console.warn("UNSAFE_SKIP_INSTALL_VERIFY is set, install payload verification is not enforced");
}

const defaultSigMaxAge = 600;

const messageHeaders = ["venndr-key-version", "venndr-timestamp", "venndr-id"];

export interface VerifierOptions {
  maxAge?: number;
}

export const verifyInstallRequest = (fetchKey: KeyFetcher, options: VerifierOptions = {}) => {
  if (process.env.UNSAFE_SKIP_INSTALL_VERIFY != null) {
    return (_: any, __: any, next: NextFunction) => next();
  }

  const maxAge: number = options.maxAge ?? defaultSigMaxAge;

  return async (req: ExRequest, _: any, next: NextFunction) => {
    if (!Buffer.isBuffer(req.body)) {
      throw new Error("expected request.body to be a Buffer");
    }

    if (!req.is("application/json")) {
      return next(
        new Error(`invalid request: expected application/json, got: ${req.header("content-type")}`),
      );
    }

    const keyVersion = req.header("venndr-key-version");

    if (!keyVersion) {
      return next(new Error("invalid request: missing venndr-key-version"));
    }

    const body = req.body as Buffer;

    if (!body || body.length == 0) {
      return next(new Error("invalid request: empty payload"));
    }

    const signature = req.header("venndr-signature");

    if (!signature) {
      return next(new Error("invalid request: signature not found"));
    }

    const currentTime = Math.floor(Date.now() / 1000); // truncate to seconds
    const age = currentTime - parseInt(req.header("venndr-timestamp") as string, 10);

    if (isNaN(age) || age < 0 || age > maxAge) {
      return next(
        new Error(
          "invalid request: signature age exceeds acceptable limit or could not be ascertained",
        ),
      );
    }

    return fetchKey(keyVersion)
      .then(async (pubkey) => {
        const message = Buffer.concat(
          [body].concat(messageHeaders.map((h) => Buffer.from(`${req.header(h)}`))),
        );
        const reqsig = Buffer.from(signature ?? "", "base64");

        if (!crypto.verify("sha256", message, pubkey, reqsig)) {
          throw new Error("invalid request: failed to verify signature");
        }

        req.body = JSON.parse(body.toString());

        next();
      })
      .catch(next);
  };
};
