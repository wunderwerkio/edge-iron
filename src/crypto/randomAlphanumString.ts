import { randomBits } from "./randomBits.js";

/**
 * Generates a cryptographically secure random alphanumeric string.
 *
 * @param length - The number of characters to generate.
 */
export const randomAlphanumString = async (length: number): Promise<string> => {
  let result = "";

  while (result.length < length) {
    const buffer = await randomBits((length + 1) * 6);
    result += buffer.toString("base64").replace(/[^a-zA-Z0-9]/g, "");
  }

  return result.slice(0, length);
};
