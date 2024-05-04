import { randomBits } from "./randomBits.js";

/**
 * Generates a cryptographically secure random string.
 *
 * @param length - The number of characters to generate.
 */
export const randomString = async (length: number): Promise<string> => {
  const buffer = await randomBits((length + 1) * 6);

  const string = buffer
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/\=/g, "");

  return string.slice(0, length);
};
