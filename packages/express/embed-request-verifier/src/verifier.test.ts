import * as crypto from "crypto";
import type { Request as ExRequest } from "express";
import type { KeyFetcher } from "@venndr/public-key-fetcher";
import { verifyEmbedRequest } from "./verifier";

const testKey = `-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAnzKquBKihkXANnvanftNv/MG3Zd4tMMj+AByMiLFrBGpiOnDfPuh
nuKszZhUGN5eC1PEFrzf5QnTK58dY2+/r2PXuZcXz3w+hwk+aC09ryboCD1Cc1ae
0Sins7p22uQyWSt0cfhun5TdeXhPhFFSQgI7DtA8sUfHE+fsYB4feOsimouNweKE
/gKb0S7yq1Bno3e1/iBsFrj26ekYOVQQ1tn5dOzmoI5zM5wKAburKZEGL4xOU/mq
kPL0nUpaxoGT8Vx3zx22yr9Y2O7CIfYGESLHSRcNYh4z2JZrPq8QgptuUAB/wCF/
vEwI/GwPk8XWswxPwbI/VXrBqtSq4/06jwIDAQAB
-----END RSA PUBLIC KEY-----`;

const pubkey = crypto.createPublicKey(Buffer.from(testKey));

const dummyKeyFetcher: KeyFetcher = (_: any): Promise<crypto.KeyObject> => Promise.resolve(pubkey);

// 2024-09-01 12:34:56 Etc/UTC
const sigt = new Date(1725194096000);

describe("embed requests verifier", () => {
  test("fails invalid signatures", async () => {
    // 2024-09-04 12:51:26 Etc/UTC
    jest.useFakeTimers().setSystemTime(new Date(1725454286000));

    const doctoredURL = {
      headers: {
        host: "example.com",
      },
      originalUrl:
        "/embed?sigt=1725454286&sigv=2022-02-14&sig=IlRk9NgyytUUSDaEnQ_7zJYfWZi6hJAskjTzwGJ-PVWcMUIA-7XotshTqIq-Vt8b896O4umVEhcBnoRKVW9rDS-qkL5Aatc40PT012_TgEv7IPijfA3M9nz69Bjf37RIUkVwGD46CNpXcNkR2MTclx9zjeMFaeMtLtYQDG7Vua_F1Usnasj4rbPdALEpeMqA3Bmf_yvjRSBdMFoJckQ9lZ-YvLUSikI46zVpSwmyHCF0xjWMI9JgUdIpDG1yS75OKtYHSQnYd8KMqa5JJAiNj9SWehgVq2n-cZi0OGzcklil4GfcdKo13_GOyFv10NRfM2T0NSnIOomIcpf8ukweFQ",
      host: "example.com",
      path: "/embed",
      protocol: "https",
      query: {
        sigt: "1725454286",
        sigv: "2022-02-14",
        sig: "IlRk9NgyytUUSDaEnQ_7zJYfWZi6hJAskjTzwGJ-PVWcMUIA-7XotshTqIq-Vt8b896O4umVEhcBnoRKVW9rDS-qkL5Aatc40PT012_TgEv7IPijfA3M9nz69Bjf37RIUkVwGD46CNpXcNkR2MTclx9zjeMFaeMtLtYQDG7Vua_F1Usnasj4rbPdALEpeMqA3Bmf_yvjRSBdMFoJckQ9lZ-YvLUSikI46zVpSwmyHCF0xjWMI9JgUdIpDG1yS75OKtYHSQnYd8KMqa5JJAiNj9SWehgVq2n-cZi0OGzcklil4GfcdKo13_GOyFv10NRfM2T0NSnIOomIcpf8ukweFQ",
      },
    };

    const kf = jest.fn(dummyKeyFetcher);
    const mw = verifyEmbedRequest(kf, { maxAge: 3 });

    let mockRequest: Partial<ExRequest>;
    let nextFn = jest.fn();

    mockRequest = {
      ...doctoredURL,
      is(x: string): string | false | null {
        return x;
      },
      header: ((name: string): string | undefined => {
        switch (name) {
          case "host":
            return doctoredURL.headers.host;
        }
        return undefined;
      }) as any,
    };

    await mw(mockRequest as any, null as any, nextFn);

    expect(kf).toHaveBeenCalledTimes(1);
    expect(kf).toHaveBeenCalledWith(doctoredURL.query.sigv);
    expect(nextFn).toHaveBeenCalledTimes(1);
    expect(nextFn.mock.calls[0][0]).toBeInstanceOf(Error);
  });

  test("fails stale signatures", async () => {
    jest.useFakeTimers().setSystemTime(new Date(sigt.getTime() + 10000));

    const staleURL = {
      headers: {
        host: "example.com",
      },
      originalUrl:
        "/embed?sigt=1725194096&sigv=2022-02-14&sig=IlRk9NgyytUUSDaEnQ_7zJYfWZi6hJAskjTzwGJ-PVWcMUIA-7XotshTqIq-Vt8b896O4umVEhcBnoRKVW9rDS-qkL5Aatc40PT012_TgEv7IPijfA3M9nz69Bjf37RIUkVwGD46CNpXcNkR2MTclx9zjeMFaeMtLtYQDG7Vua_F1Usnasj4rbPdALEpeMqA3Bmf_yvjRSBdMFoJckQ9lZ-YvLUSikI46zVpSwmyHCF0xjWMI9JgUdIpDG1yS75OKtYHSQnYd8KMqa5JJAiNj9SWehgVq2n-cZi0OGzcklil4GfcdKo13_GOyFv10NRfM2T0NSnIOomIcpf8ukweFQ",
      host: "example.com",
      path: "/embed",
      protocol: "https",
      query: {
        sigt: "1725194096",
        sigv: "2022-02-14",
        sig: "IlRk9NgyytUUSDaEnQ_7zJYfWZi6hJAskjTzwGJ-PVWcMUIA-7XotshTqIq-Vt8b896O4umVEhcBnoRKVW9rDS-qkL5Aatc40PT012_TgEv7IPijfA3M9nz69Bjf37RIUkVwGD46CNpXcNkR2MTclx9zjeMFaeMtLtYQDG7Vua_F1Usnasj4rbPdALEpeMqA3Bmf_yvjRSBdMFoJckQ9lZ-YvLUSikI46zVpSwmyHCF0xjWMI9JgUdIpDG1yS75OKtYHSQnYd8KMqa5JJAiNj9SWehgVq2n-cZi0OGzcklil4GfcdKo13_GOyFv10NRfM2T0NSnIOomIcpf8ukweFQ",
      },
    };

    const kf = jest.fn(dummyKeyFetcher);
    const mw = verifyEmbedRequest(kf, { maxAge: 3 });

    let mockRequest: Partial<ExRequest>;
    let nextFn = jest.fn();

    mockRequest = {
      ...staleURL,
      is(x: string): string | false | null {
        return x;
      },
      header: ((name: string): string | undefined => {
        switch (name) {
          case "host":
            return staleURL.headers.host;
        }
        return undefined;
      }) as any,
    };

    await mw(mockRequest as any, null as any, nextFn);

    expect(kf).not.toHaveBeenCalled();
    expect(nextFn).toHaveBeenCalledTimes(1);
    expect(nextFn.mock.calls[0][0]).toBeInstanceOf(Error);
  });

  test("passes for valid requests", async () => {
    jest.useFakeTimers().setSystemTime(new Date(sigt.getTime() + 3000));

    const validURL = {
      headers: {
        host: "example.com",
      },
      originalUrl:
        "/embed?sigt=1725194096&sigv=2022-02-14&sig=IlRk9NgyytUUSDaEnQ_7zJYfWZi6hJAskjTzwGJ-PVWcMUIA-7XotshTqIq-Vt8b896O4umVEhcBnoRKVW9rDS-qkL5Aatc40PT012_TgEv7IPijfA3M9nz69Bjf37RIUkVwGD46CNpXcNkR2MTclx9zjeMFaeMtLtYQDG7Vua_F1Usnasj4rbPdALEpeMqA3Bmf_yvjRSBdMFoJckQ9lZ-YvLUSikI46zVpSwmyHCF0xjWMI9JgUdIpDG1yS75OKtYHSQnYd8KMqa5JJAiNj9SWehgVq2n-cZi0OGzcklil4GfcdKo13_GOyFv10NRfM2T0NSnIOomIcpf8ukweFQ",
      host: "example.com",
      path: "/embed",
      protocol: "https",
      query: {
        sigt: "1725194096",
        sigv: "2022-02-14",
        sig: "IlRk9NgyytUUSDaEnQ_7zJYfWZi6hJAskjTzwGJ-PVWcMUIA-7XotshTqIq-Vt8b896O4umVEhcBnoRKVW9rDS-qkL5Aatc40PT012_TgEv7IPijfA3M9nz69Bjf37RIUkVwGD46CNpXcNkR2MTclx9zjeMFaeMtLtYQDG7Vua_F1Usnasj4rbPdALEpeMqA3Bmf_yvjRSBdMFoJckQ9lZ-YvLUSikI46zVpSwmyHCF0xjWMI9JgUdIpDG1yS75OKtYHSQnYd8KMqa5JJAiNj9SWehgVq2n-cZi0OGzcklil4GfcdKo13_GOyFv10NRfM2T0NSnIOomIcpf8ukweFQ",
      },
    };

    const kf = jest.fn(dummyKeyFetcher);
    const mw = verifyEmbedRequest(kf);

    let mockRequest: Partial<ExRequest>;
    let nextFn = jest.fn();

    mockRequest = {
      ...validURL,
      is(x: string): string | false | null {
        return x;
      },
      header: ((name: string): string | undefined => {
        switch (name) {
          case "host":
            return validURL.headers.host;
        }
        return undefined;
      }) as any,
    };

    await mw(mockRequest as any, null as any, nextFn);

    expect(kf).toHaveBeenCalledTimes(1);
    expect(kf).toHaveBeenCalledWith(validURL.query.sigv);
    expect(nextFn).toHaveBeenCalled();
    expect(nextFn).toHaveBeenCalledTimes(1);
    expect(nextFn.mock.calls[0]).toEqual([]);
  });

  test("passes for proxied requests", async () => {
    jest.useFakeTimers().setSystemTime(new Date(sigt.getTime() + 3000));

    const validURL = {
      headers: {
        "x-forwarded-host": "example.com",
        host: "app-server.internal-vpc.com",
      },
      originalUrl:
        "/embed?sigt=1725194096&sigv=2022-02-14&sig=IlRk9NgyytUUSDaEnQ_7zJYfWZi6hJAskjTzwGJ-PVWcMUIA-7XotshTqIq-Vt8b896O4umVEhcBnoRKVW9rDS-qkL5Aatc40PT012_TgEv7IPijfA3M9nz69Bjf37RIUkVwGD46CNpXcNkR2MTclx9zjeMFaeMtLtYQDG7Vua_F1Usnasj4rbPdALEpeMqA3Bmf_yvjRSBdMFoJckQ9lZ-YvLUSikI46zVpSwmyHCF0xjWMI9JgUdIpDG1yS75OKtYHSQnYd8KMqa5JJAiNj9SWehgVq2n-cZi0OGzcklil4GfcdKo13_GOyFv10NRfM2T0NSnIOomIcpf8ukweFQ",
      host: "example.com",
      path: "/embed",
      protocol: "https",
      query: {
        sigt: "1725194096",
        sigv: "2022-02-14",
        sig: "IlRk9NgyytUUSDaEnQ_7zJYfWZi6hJAskjTzwGJ-PVWcMUIA-7XotshTqIq-Vt8b896O4umVEhcBnoRKVW9rDS-qkL5Aatc40PT012_TgEv7IPijfA3M9nz69Bjf37RIUkVwGD46CNpXcNkR2MTclx9zjeMFaeMtLtYQDG7Vua_F1Usnasj4rbPdALEpeMqA3Bmf_yvjRSBdMFoJckQ9lZ-YvLUSikI46zVpSwmyHCF0xjWMI9JgUdIpDG1yS75OKtYHSQnYd8KMqa5JJAiNj9SWehgVq2n-cZi0OGzcklil4GfcdKo13_GOyFv10NRfM2T0NSnIOomIcpf8ukweFQ",
      },
    };

    const kf = jest.fn(dummyKeyFetcher);
    const mw = verifyEmbedRequest(kf);

    let mockRequest: Partial<ExRequest>;
    let nextFn = jest.fn();

    mockRequest = {
      ...validURL,
      is(x: string): string | false | null {
        return x;
      },
      header: ((name: string): string | undefined => {
        switch (name) {
          case "host":
            return validURL.headers.host;
        }
        return undefined;
      }) as any,
    };

    await mw(mockRequest as any, null as any, nextFn);

    expect(kf).toHaveBeenCalledTimes(1);
    expect(kf).toHaveBeenCalledWith(validURL.query.sigv);
    expect(nextFn).toHaveBeenCalled();
    expect(nextFn).toHaveBeenCalledTimes(1);
    expect(nextFn.mock.calls[0]).toEqual([]);
  });
});
