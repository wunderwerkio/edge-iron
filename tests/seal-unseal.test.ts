import test from "ava";
import { seal } from "../src/seal.js";
import { defaults, macPrefix } from "../src/constants.js";
import { unseal } from "../src/unseal.js";

const algorithms = ["AES-CTR", "AES-CBC"] as const;

const payload = {
  hello: "world",
};

algorithms.forEach((algorithm) => {
  test(`seal and unseal valid payload - ${algorithm}`, async (t) => {
    const payload = {
      hello: "world",
    };
    const password = "some_not_random_password_that_is_at_least_32_characters";
    const sealed = await seal(payload, password, defaults);

    t.is(typeof sealed, "string");
    t.assert(sealed.startsWith(macPrefix));

    const unsealed = await unseal<typeof payload>(sealed, password, defaults);

    t.deepEqual(unsealed, payload);
  });

  test(`should not unseal value with wrong password - ${algorithm}`, async (t) => {
    const payload = {
      hello: "world",
    };
    let password = "some_not_random_password_that_is_at_least_32_characters";
    const sealed = await seal(payload, password, defaults);

    password = "changed_not_random_password_that_is_at_least_32_characters";

    await t.throwsAsync(
      async () => {
        await unseal<typeof payload>(sealed, password, defaults);
      },
      { message: "Bad hmac value" }
    );
  });

  test(`should seal and unseal with password id - ${algorithm}`, async (t) => {
    const payload = {
      hello: "world",
    };

    const password = {
      id: "specific",
      encryption: "drfqgL7YYfzssfzssj7mrEStYbB87IqmmPC7m",
      integrity: "gOssDKlDKl42X22v6Y6uZSDZaf7GyaoS9uUS",
    };

    const sealed = await seal(payload, password, defaults);
    const unsealed = await unseal<typeof payload>(
      sealed,
      {
        [password.id]: password,
      },
      defaults
    );

    t.deepEqual(unsealed, payload);
  });

  test(`should not unseal value with invalid encrypted string - ${algorithm}`, async (t) => {
    const payload = {
      hello: "world",
    };
    const password = "some_not_random_password_that_is_at_least_32_characters";
    const sealed = await seal(payload, password, defaults);

    const modifiedSealed = sealed
      .split("*")
      .map((part, index) => {
        if (index === 4) {
          return "zw4eiR44m-FVpPc4sRVTemczr9K-4e9bv2JzPJmBH0Y";
        }

        return part;
      })
      .join("*");

    await t.throwsAsync(
      async () => {
        await unseal<typeof payload>(modifiedSealed, password, defaults);
      },
      { message: "Bad hmac value" }
    );
  });
});

test("Unseal function - Expired seal", async (t) => {
  const password = "your-password-string-ultra-secure";
  const options = {
    ...defaults,
    ttl: 100,
    timestampSkewSec: 0,
  };

  const sealed = await seal(payload, password, options);

  await new Promise((resolve) => setTimeout(resolve, 100));

  await t.throwsAsync(
    async () => {
      await unseal(sealed, password, options);
    },
    { message: "Expired seal" }
  );
});

test("Unseal function - Expired seal with skew", async (t) => {
  const password = "your-password-string-ultra-secure";
  const options = {
    ...defaults,
    ttl: 100,
    timestampSkewSec: 0.1,
  };

  const sealed = await seal(payload, password, options);

  await new Promise((resolve) => setTimeout(resolve, 200));

  await t.throwsAsync(
    async () => {
      await unseal(sealed, password, options);
    },
    { message: "Expired seal" }
  );
});
