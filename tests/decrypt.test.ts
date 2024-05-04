import test from "ava";
import { algorithms } from "../src/constants.js";
import { encrypt } from "../src/encrypt.js";
import { decrypt } from "../src/decrypt.js";
import { randomBits } from "../src/crypto/index.js";

const testAlgorithms = [
  "AES-CTR",
  "AES-CBC",
] as const;

testAlgorithms.forEach((algorithm) => {
  test(`should return decrypt payload - ${algorithm}`, async (t) => {
    const password = "password";
    const options = {
      algorithm,
      minPasswordlength: 5,
      saltBits: 10,
      iterations: 1,
      salt: '3e2e',
      iv: await randomBits(algorithms[algorithm].ivBits)
    };

    const { encrypted } = await encrypt(password, options, "Test data");
    const decrypted = await decrypt(
      password,
      options,
      encrypted,
    );

    t.is(decrypted, "Test data");
  });
});
