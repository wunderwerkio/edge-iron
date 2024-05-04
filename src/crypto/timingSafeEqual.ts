/**
 * Implements Crypto.timingSafeEqual() to be compatible with Edge runtime.
 *
 * Compares two Buffer objects for equality in a way that defends against timing attacks.
 * Returns true if the buffers are equal and false otherwise.
 *
 * @param a - The first buffer to compare.
 * @param b - The second buffer to compare.
 */
export const timingSafeEqual = (a: Buffer, b: Buffer): boolean => {
  if (a.length !== b.length) {
    return false;
  }

  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }

  return diff === 0;
};
