import * as crypto from "crypto";
import type { Request as ExRequest } from "express";
import type { KeyFetcher } from "@venndr/public-key-fetcher";
import { verifyInstallRequest } from "./verifier";

const testKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzKquBKihkXANnvanftN
v/MG3Zd4tMMj+AByMiLFrBGpiOnDfPuhnuKszZhUGN5eC1PEFrzf5QnTK58dY2+/
r2PXuZcXz3w+hwk+aC09ryboCD1Cc1ae0Sins7p22uQyWSt0cfhun5TdeXhPhFFS
QgI7DtA8sUfHE+fsYB4feOsimouNweKE/gKb0S7yq1Bno3e1/iBsFrj26ekYOVQQ
1tn5dOzmoI5zM5wKAburKZEGL4xOU/mqkPL0nUpaxoGT8Vx3zx22yr9Y2O7CIfYG
ESLHSRcNYh4z2JZrPq8QgptuUAB/wCF/vEwI/GwPk8XWswxPwbI/VXrBqtSq4/06
jwIDAQAB
-----END PUBLIC KEY-----`;

const pubkey = crypto.createPublicKey(Buffer.from(testKey));
const fakeNow = new Date(Date.parse("2025-08-29 11:34:15Z"));
const installPayload = `{"api_token":"SFMyNTY.g2gDbQAAACQ4ZjMxODQ4MC1mOTY1LTRhNWYtYjUwYi05ZTcxY2Y3NTBmN2NuBgA4X8f1mAFiAAFRgA.pxABVzYKfyv3UIygERf9i-IWeRRjVzcqKGyFKSqDopQ","store_id":"a9da1df7-03c4-4e71-add4-1f3846b7d527"}`;
const installHeaders = {
  "venndr-id": "d94fd13f-59f2-4490-96c4-1146c54c8f78",
  "venndr-key-version": "2022-02-14",
  "venndr-signature":
    "K0PeQrKFDaKdG1V/pawTd4wbEK0IzLFrtfFHhGjv2EopIO2lom0KLVlFqVs8LZdntlDyOYDEJ6CriSFj4HIivLZl9dkn1OcbGr7V412Mp3ohYfKclnckJDJ3jcBj3ZZUVDG0kQ/OPPT4QN7o8CuyxwJDC2Jv/WJLkTtJ+ZrSgM9iJDWREU0CKHHawEZGbgHbnByGbCC/fgh528SDdqficqfdoRvgjt44MZnugyWuNym3xeE2V7CEW2L7Ty52NbnckxR5JJMt6FZxtP8YbDsmIGSbJbp5Twx+NZ4a+TV/nvoZrTV17ZDULDDXZiXlM80qcIInQ047s2E+54SQkIfmpA==",
  "venndr-timestamp": "1756467255",
};

const dummyKeyFetcher: KeyFetcher = (_: any): Promise<crypto.KeyObject> => Promise.resolve(pubkey);

describe("install requests verifier", () => {
  test("passes for valid requests", async () => {
    jest.useFakeTimers().setSystemTime(new Date(fakeNow.getTime() + 3000));

    const baseRequest = {
      headers: Object.assign(
        {
          host: "example.com",
        },
        installHeaders,
      ),
      originalUrl: "/install",
      host: "example.com",
      path: "/install",
      protocol: "https",
      query: {},
    };

    const kf = jest.fn(dummyKeyFetcher);
    const mw = verifyInstallRequest(kf);

    let mockRequest: Partial<ExRequest>;
    let nextFn = jest.fn();

    mockRequest = {
      ...baseRequest,
      is(x: string): string | false | null {
        return x;
      },
      header: ((name: keyof (typeof baseRequest)["headers"]): string | undefined => {
        return baseRequest.headers[name];
      }) as any,
      body: Buffer.from(installPayload),
    };

    await mw(mockRequest as any, null as any, nextFn);

    expect(nextFn).toHaveBeenCalled();
    expect(nextFn).toHaveBeenCalledTimes(1);
    expect(nextFn.mock.calls[0]).toEqual([]);
    expect(kf).toHaveBeenCalledTimes(1);
  });

  test("fails mismatching signatures", async () => {
    // 2024-09-04 12:51:26 Etc/UTC
    jest.useFakeTimers().setSystemTime(new Date(fakeNow.getTime() + 30000));

    const baseRequest = {
      headers: Object.assign(
        {
          host: "example.com",
        },
        installHeaders,
      ),
      originalUrl: "/install",
      host: "example.com",
      path: "/install",
      protocol: "https",
      query: {},
    };

    const kf = jest.fn(dummyKeyFetcher);
    const mw = verifyInstallRequest(kf);

    let mockRequest: Partial<ExRequest>;
    let nextFn = jest.fn();

    mockRequest = {
      ...baseRequest,
      is(x: string): string | false | null {
        return x;
      },
      header: ((name: string): string | undefined => {
        switch (name) {
          case "host":
            return baseRequest.headers.host;
        }
        return undefined;
      }) as any,
      body: Buffer.from(`${installPayload.slice(0, -1)},"extra":"poop"}`),
    };

    await mw(mockRequest as any, null as any, nextFn);

    expect(nextFn).toHaveBeenCalled();
    expect(nextFn).toHaveBeenCalledTimes(1);
    expect(nextFn.mock.calls[0][0]).toBeInstanceOf(Error);
  });

  test("fails stale signatures", async () => {
    jest.useFakeTimers().setSystemTime(new Date(fakeNow.getTime() + 60000));

    const baseRequest = {
      headers: Object.assign(
        {
          host: "example.com",
        },
        installHeaders,
      ),
      originalUrl: "/install",
      host: "example.com",
      path: "/install",
      protocol: "https",
      query: {},
    };

    const kf = jest.fn(dummyKeyFetcher);
    const mw = verifyInstallRequest(kf, { maxAge: 3 });

    let mockRequest: Partial<ExRequest>;
    let nextFn = jest.fn();

    mockRequest = {
      ...baseRequest,
      is(x: string): string | false | null {
        return x;
      },
      header: ((name: string): string | undefined => {
        switch (name) {
          case "host":
            return baseRequest.headers.host;
        }
        return undefined;
      }) as any,
      body: Buffer.from(installPayload),
    };

    await mw(mockRequest as any, null as any, nextFn);

    expect(kf).not.toHaveBeenCalled();
    expect(nextFn).toHaveBeenCalledTimes(1);
    expect(nextFn.mock.calls[0][0]).toBeInstanceOf(Error);
  });
});
