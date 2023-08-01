import test from "ava";
import { encrypt } from "../src/encrypt.js";
import { Key } from "../src/types.js";

const algorithms = ["AES-CTR", "AES-CBC"] as const;

algorithms.forEach((algorithm) => {
  test(`should return encrypted Buffer and key when password, options and data are provided - ${algorithm}`, async (t) => {
    const result = await encrypt(
      "password",
      {
        algorithm,
        minPasswordlength: 5,
        saltBits: 10,
        iterations: 1,
      },
      "Test data"
    );

    t.true(Buffer.isBuffer(result.encrypted));
    t.true((result.key as Key).key !== undefined);
    t.true((result.key as Key).salt !== undefined);
  });
});
