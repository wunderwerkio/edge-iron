import { Buffer } from "buffer";

/**
 * Implements Crypto.randomBytes() using the Web Crypto API.
 *
 * @param size - The number of bytes to generate.
 */
export const randomBytes = async (size: number): Promise<Buffer> => {
  if (!globalThis.crypto) {
    // @ts-ignore
    globalThis.crypto = await import("crypto");
  }

  const array = new Uint8Array(size);

  crypto.getRandomValues(array);

  return Buffer.from(array.buffer);
};
