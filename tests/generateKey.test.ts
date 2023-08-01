import test from "ava";
import { generateKey } from "../src/generateKey.js";
import type { IronAlgorithms } from "../src/constants.js";
import { Key } from "../src/types.js";

const algorithms = [
  "AES-CTR",
  "AES-CBC",
] as (keyof IronAlgorithms)[];

algorithms.forEach((algorithm) => {
  test(`should throw an error when no password is provided - ${algorithm}`, async (t) => {
    await t.throwsAsync(
      async () => {
        await generateKey("", {
          algorithm,
          minPasswordlength: 5,
          saltBits: 10,
          iterations: 1,
        });
      },
      { message: "Empty password" }
    );
  });

  test(`should throw an error when options are not provided - ${algorithm}`, async (t) => {
    await t.throwsAsync(
      async () => {
        // @ts-expect-error
        await generateKey("password", null);
      },
      { message: "Bad options" }
    );
  });

  test(`should throw an error when password length is less than minimum required - ${algorithm}`, async (t) => {
    await t.throwsAsync(
      async () => {
        await generateKey("pass", {
          algorithm,
          minPasswordlength: 5,
          saltBits: 10,
          iterations: 1,
        });
      },
      { message: "Password string too short (min 5 characters required)" }
    );
  });

  test(`should throw an error when no salt or saltBits are provided - ${algorithm}`, async (t) => {
    await t.throwsAsync(
      async () => {
        await generateKey("password", {
          algorithm,
          minPasswordlength: 5,
          iterations: 1,
        });
      },
      { message: "Missing salt and saltBits options" }
    );
  });

  test(`should return a Key when proper password and options are provided - ${algorithm}`, async (t) => {
    const result = await generateKey("password", {
      algorithm,
      minPasswordlength: 5,
      saltBits: 10,
      iterations: 1,
    });

    t.true((result as Key).key !== undefined);
    t.true((result as Key).salt !== undefined);
  });
});

test("should throw an error when unknown algorithm is provided", async (t) => {
  await t.throwsAsync(
    async () => {
      await generateKey("password", {
        // @ts-expect-error
        algorithm: "unknown",
        minPasswordlength: 5,
        saltBits: 10,
        iterations: 1,
      });
    },
    { message: "Unknown algorithm: unknown" }
  );
});
