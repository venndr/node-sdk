import * as crypto from "crypto";
import { Request as ExRequest } from "express";
import { verifyWebhookSignature } from "./webhook-verifier";
import type { KeyFetcher } from "@venndr/public-key-fetcher";

const testKey = `-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAnzKquBKihkXANnvanftNv/MG3Zd4tMMj+AByMiLFrBGpiOnDfPuh
nuKszZhUGN5eC1PEFrzf5QnTK58dY2+/r2PXuZcXz3w+hwk+aC09ryboCD1Cc1ae
0Sins7p22uQyWSt0cfhun5TdeXhPhFFSQgI7DtA8sUfHE+fsYB4feOsimouNweKE
/gKb0S7yq1Bno3e1/iBsFrj26ekYOVQQ1tn5dOzmoI5zM5wKAburKZEGL4xOU/mq
kPL0nUpaxoGT8Vx3zx22yr9Y2O7CIfYGESLHSRcNYh4z2JZrPq8QgptuUAB/wCF/
vEwI/GwPk8XWswxPwbI/VXrBqtSq4/06jwIDAQAB
-----END RSA PUBLIC KEY-----`;

const testHeaders = new Map(
  `Venndr-Id: b2bd8273-8991-4d6a-b625-88af91d2d04d
Venndr-Platform-Handle: platform
Venndr-Platform-Id: 5020e8a0-3266-4b7c-8a90-f0ce2f5c1087
Venndr-Store-Handle: store
Venndr-Store-Id: a5902e6b-5513-4603-b5ba-d0504d890db7
Venndr-Topic: testing
Venndr-Version: 1
Venndr-Key-Version: testing
Venndr-Signature: l2YqsY6wo689LgUG7uwSI3Jzseqkso7LyWlDZEdGg6Dc+2p0d32/OXT1VHhsmWuIhIIh7+OvU/0zT5VD2RDsO4PNLLFmhul+OiVa1v0/jWbWEeJDqm0vOdfVGyqLETLecSBtDhO7gziwUSrJsLnptoyvxgvhmCzuV9fBp0ObP0ekA6CN1Uxn33kIhPM7iETFRbEpi8uA1drsF0vcMDjz4b6tSROzhtcp2aY/AfpqbbiVJJZ4sjwPamIJNa2RMzOsdBzt8RYwmrabd6NNfvtf3GGdL/gc0vkKAZSuRwjQBDPKq/arzb0s0q4/kNIVg/tUcg++dsOqd3XtxYHbNLPI8g==
Venndr-Timestamp: 1689079288`
    .split("\n")
    .map((s) => s.split(": ", 2))
    .map(([k, v]) => [k!.toLowerCase().trim(), v!.trim()]),
);

const getHeader = (name: string) => testHeaders.get(name.toLowerCase());

const testPayload = `{"action":"testing","payload":{"created_at":"2023-07-11T12:41:18.671870Z","message":"Testing 1..2..3! Beep boop, bleep bloop!"},"platform_id":"5020e8a0-3266-4b7c-8a90-f0ce2f5c1087","request_id":"b2bd8273-8991-4d6a-b625-88af91d2d04d","store_id":"a5902e6b-5513-4603-b5ba-d0504d890db7","topic":"testing","version":"1"}`;

const keyBytes = Buffer.from(testKey);
const key = crypto.createPublicKey(keyBytes);

const dummyKeyFetcher: KeyFetcher = (_: any): Promise<crypto.KeyObject> => Promise.resolve(key);

describe("webhook verifier", () => {
  test("passes for valid payloads", async () => {
    const kf = jest.fn(dummyKeyFetcher);
    const mw = verifyWebhookSignature(kf);

    let mockRequest: Partial<ExRequest>;
    let nextFn = jest.fn();

    mockRequest = {
      is(x: string): string | false | null {
        return x;
      },
      body: Buffer.from(testPayload),
      header: getHeader as any,
    };

    await mw(mockRequest as any, null as any, nextFn);

    expect(kf).toHaveBeenCalled();
    expect(nextFn).toHaveBeenCalled();
    expect(mockRequest.body).toEqual(JSON.parse(testPayload));
  });

  test("fails invalid payloads", async () => {
    const kf = jest.fn(dummyKeyFetcher);
    const mw = verifyWebhookSignature(kf);

    let mockRequest: Partial<ExRequest>;
    let nextFn = jest.fn();

    mockRequest = {
      is(x: string): string | false | null {
        return x;
      },
      body: Buffer.from("beep boop bleep bloop"),
      header: getHeader as any,
    };

    await mw(mockRequest as any, null as any, nextFn);

    expect(kf).toHaveBeenCalled();
    expect(nextFn).toHaveBeenCalled();
    expect(nextFn.mock.calls[0][0]).toBeInstanceOf(Error);
  });

  test("fails invalid requests", async () => {
    const req: Partial<ExRequest> = {
      is(_: string): string | false | null {
        return false;
      },

      header(_): any {
        return "not json";
      },

      body: Buffer.from("beep boop"),
    };

    const kf = jest.fn();
    const mw = verifyWebhookSignature(kf);

    const nextFn = jest.fn();

    await mw(req as any, undefined as any, nextFn);

    expect(nextFn).toHaveBeenCalled();
    expect(nextFn.mock.calls[0][0]).toBeInstanceOf(Error);
  });
});
