import { randomBytes } from "./randomBytes.js";

/**
 * Create cryptographically secure random digits.
 *
 * @param length - The number of digits to generate.
 */
export const randomDigits = async (length: number): Promise<string> => {
  const digits = [];

  let buffer = await randomBytes(length * 2); // Provision twice the amount of bytes needed to increase chance of single pass
  let pos = 0;

  while (digits.length < length) {
    if (pos >= buffer.length) {
      buffer = await randomBytes(length * 2);
      pos = 0;
    }

    if (buffer[pos] < 250) {
      digits.push(buffer[pos] % 10);
    }

    ++pos;
  }

  return digits.join("");
};
