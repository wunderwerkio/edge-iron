import test from "ava";
import { hmacWithPassword } from "../src/hmacWithPassword.js";

test("create hmac from password", async (t) => {
  const { digest } = await hmacWithPassword(
    "password",
    {
      algorithm: "SHA-256",
      minPasswordlength: 5,
      saltBits: 10,
      iterations: 1,
    },
    "test-abc"
  );

  t.is(digest.length, 43);
});
