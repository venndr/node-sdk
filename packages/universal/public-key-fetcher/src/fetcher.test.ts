import { keyFetcher } from "./fetcher";

const testKey = `-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAnzKquBKihkXANnvanftNv/MG3Zd4tMMj+AByMiLFrBGpiOnDfPuh
nuKszZhUGN5eC1PEFrzf5QnTK58dY2+/r2PXuZcXz3w+hwk+aC09ryboCD1Cc1ae
0Sins7p22uQyWSt0cfhun5TdeXhPhFFSQgI7DtA8sUfHE+fsYB4feOsimouNweKE
/gKb0S7yq1Bno3e1/iBsFrj26ekYOVQQ1tn5dOzmoI5zM5wKAburKZEGL4xOU/mq
kPL0nUpaxoGT8Vx3zx22yr9Y2O7CIfYGESLHSRcNYh4z2JZrPq8QgptuUAB/wCF/
vEwI/GwPk8XWswxPwbI/VXrBqtSq4/06jwIDAQAB
-----END RSA PUBLIC KEY-----`;

describe("key fetcher", () => {
  test("it caches keys on fetch by default", async () => {
    const res: Partial<Response> = {
      get ok() {
        return true;
      },

      arrayBuffer() {
        return Promise.resolve(new TextEncoder().encode(testKey).buffer);
      },

      get body() {
        return new ReadableStream<Uint8Array>({
          start(c) {
            c.enqueue(new TextEncoder().encode(testKey));
            c.close();
          },
        });
      },
    };

    const kf = jest.fn(() => Promise.resolve(res));
    const f = keyFetcher({ fetch: kf as any });

    await f("beep");
    await f("boop");
    await f("beep");
    await f("boop");

    expect(kf).toHaveBeenCalledTimes(2);
  });

  test("it returns error on a non-200 response", async () => {
    const res: Partial<Response> = {
      get ok() {
        return false;
      },
      get status() {
        return 404;
      },
      get body() {
        return null;
      },
    };

    const kf = jest.fn(() => Promise.resolve(res));
    const f = keyFetcher({ fetch: kf as any });

    await expect(() => f("boop")).rejects.toThrow();

    expect(kf).toHaveBeenCalledTimes(1);
  });
});
