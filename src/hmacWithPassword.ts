import { Buffer } from "buffer";
import { generateKey } from "./generateKey.js";
import { HMacOptions, HMacResult, Password } from "./types.js";

export const hmacWithPassword = async (
  password: Password,
  options: HMacOptions,
  data: string
): Promise<HMacResult> => {
  const key = await generateKey(password, options);
  const encodedData = new TextEncoder().encode(data);

  if (!globalThis.crypto) {
    // @ts-ignore
    crypto = await import("crypto");
  }

  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key.key,
    { name: "HMAC", hash: options.algorithm },
    false,
    ["sign"]
  );

  const hmacArrayBuffer = await crypto.subtle.sign(
    "HMAC",
    cryptoKey,
    encodedData
  );

  const base64String = Buffer.from(hmacArrayBuffer).toString("base64");

  const digest = base64String
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");

  return {
    digest,
    salt: key.salt,
  };
};
