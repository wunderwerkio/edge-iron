import { EncryptionOptions, Password } from "./types.js";
import { generateKey } from "./generateKey.js";

export const decrypt = async (
  password: Password,
  options: EncryptionOptions,
  data: Buffer
): Promise<string> => {
  const key = await generateKey(password, options);

  if (!globalThis.crypto) {
    // @ts-ignore
    crypto = await import("crypto");
  }

  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key.key,
    {
      name: options.algorithm,
      length: key.key.byteLength * 8,
    },
    false,
    ["decrypt"]
  );

  const decrypted = await crypto.subtle.decrypt(
    {
      name: options.algorithm,
      iv: key.iv,
      counter: key.iv,
      length: key.key.byteLength * 8,
    },
    cryptoKey,
    data
  );

  return Buffer.from(decrypted).toString("utf8");
};
