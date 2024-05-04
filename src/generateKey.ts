import { Buffer } from "buffer";
import { pbkdf2, randomBits } from "./crypto/index.js";
 

import { algorithms } from "./constants.js";
import { GenerateKeyOptions, Key, Password } from "./types.js";

export const generateKey = async (
  password: Password,
  options: GenerateKeyOptions
): Promise<Key> => {
  if (!password) {
    throw new Error("Empty password");
  }

  if (!options || typeof options !== "object") {
    throw new Error("Bad options");
  }

  const algorithm = algorithms[options.algorithm];
  if (!algorithm) {
    throw new Error("Unknown algorithm: " + options.algorithm);
  }

  const result: Partial<Key> = {};

  if (Buffer.isBuffer(password)) {
    if (password.length < algorithm.keyBits / 8) {
      throw new Error("Key buffer (password) too small");
    }

    result.key = password;
    result.salt = "";
  } else {
    if (password.length < options.minPasswordlength) {
      throw new Error(
        "Password string too short (min " +
          options.minPasswordlength +
          " characters required)"
      );
    }

    let salt = options.salt;
    if (!salt) {
      if (!options.saltBits) {
        throw new Error("Missing salt and saltBits options");
      }

      const randomSalt = await randomBits(options.saltBits);
      salt = randomSalt.toString("hex");
    }

    const derivedKey = await pbkdf2(
      password,
      salt,
      options.iterations,
      algorithm.keyBits / 8,
      "SHA-1"
    );

    result.key = derivedKey;
    result.salt = salt;
  }

  if (options.iv) {
    result.iv = options.iv;
  } else if ("ivBits" in algorithm) {
    result.iv = await randomBits(algorithm.ivBits);
  }

  return result as Key;
};
