import * as crypto from "crypto";
import { KeyFetcher } from "@venndr/public-key-fetcher";
import { Request as ExRequest, NextFunction } from "express";

// source https://github.com/joaquimserafim/base64-url/blob/master/index.js
function unescapeBase64url(str: string): string {
  return (str + "===".slice((str.length + 3) % 4)).replace(/-/g, "+").replace(/_/g, "/");
}

const defaultSigMaxAge = 600;

export interface VerifierOptions {
  fetchKey?: KeyFetcher;
  maxAge?: number;
}

export const verifyEmbedRequest = (fetchKey: KeyFetcher, options: VerifierOptions = {}) => {
  const maxAge: number = options.maxAge ?? defaultSigMaxAge;

  return async (rq: ExRequest, _: any, next: NextFunction) => {
    const currentTime = Math.floor(Date.now() / 1000); // truncate to seconds
    const age = currentTime - parseInt(rq.query.sigt as string, 10);
    const sigv = rq.query.sigv as string;

    if (isNaN(age) || age < 0 || age > maxAge) {
      next(new Error("signature age exceeds acceptable limit or could not be ascertained"));
      return;
    }

    return fetchKey(sigv)
      .then((pubkey) => {
        const remainder = rq.originalUrl.slice(0, rq.originalUrl.lastIndexOf("&"));
        const message = Buffer.from(`${rq.protocol}://${rq.headers.host}${remainder}`);
        const sig = Buffer.from(unescapeBase64url(rq.query.sig as string), "base64");
        const authn = crypto.verify("sha256", message, pubkey, sig);

        if (!authn) {
          next(new Error("request authenticity could not be verified"));
          return;
        }

        next();
      })
      .catch(next);
  };
};
