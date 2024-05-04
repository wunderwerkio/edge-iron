import { Buffer } from "buffer";
import { randomBytes } from "./randomBytes.js";

/**
 * Same as randomBytes() but for bits.
 *
 * @param bits - The number of bits to generate.
 */
export const randomBits = async (bits: number): Promise<Buffer> => {
  if (!bits || bits < 0) {
    throw new Error("Invalid bits count!");
  }

  const bytes = Math.ceil(bits / 8);

  return await randomBytes(bytes);
};
