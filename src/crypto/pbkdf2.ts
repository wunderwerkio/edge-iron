import { Buffer } from "buffer";

type DigestAlgorithm = "SHA-1" | "SHA-256" | "SHA-384" | "SHA-512";

/**
 * Implements Crypto.pbkdf2() function using Web Crypto API:
 *
 * @param password - The password to generate the key for.
 * @param salt - Salt to be used during key generation.
 * @param iterations - Number of iterations to be used during key generation.
 * @param keylen - Length of the key to be generated.
 * @param digest - Digest algorithm to be used during key generation.
 */
export const pbkdf2 = async (
  password: string,
  salt: string,
  iterations: number,
  keylen: number,
  digest: DigestAlgorithm
): Promise<Buffer> => {
  const encoder = new TextEncoder();

  if (!globalThis.crypto) {
    // @ts-ignore
    globalThis.crypto = await import("crypto");
  }

  const baseKey = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey", "deriveBits"]
  );

  const derivedKey = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: encoder.encode(salt),
      iterations: iterations,
      hash: { name: digest },
    },
    baseKey,
    keylen * 8
  );

  return Buffer.from(derivedKey);
};
