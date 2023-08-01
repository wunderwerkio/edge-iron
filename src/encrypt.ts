import { Buffer } from "buffer";
import { EncryptionOptions, Key, Password } from "./types.js";
import { generateKey } from "./generateKey.js";

export const encrypt = async (
  password: Password,
  options: EncryptionOptions,
  data: string
): Promise<{ encrypted: Buffer; key: Key }> => {
  const key = await generateKey(password, options);
  const encodedData = new TextEncoder().encode(data);

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
    ["encrypt"]
  );

  const encrypted = await crypto.subtle.encrypt(
    {
      name: options.algorithm,
      iv: key.iv,
      counter: key.iv,
      length: key.key.byteLength * 8,
    },
    cryptoKey,
    encodedData
  );

  return { encrypted: Buffer.from(encrypted), key };
};
