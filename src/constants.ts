import { SealOptions } from "./types.js";

export const defaults: SealOptions = {
  encryption: {
    saltBits: 256,
    algorithm: "AES-CBC",
    iterations: 1,
    minPasswordlength: 32,
  },

  integrity: {
    saltBits: 256,
    algorithm: "SHA-256",
    iterations: 1,
    minPasswordlength: 32,
  },

  ttl: 0, // Milliseconds, 0 means forever
  timestampSkewSec: 60, // Seconds of permitted clock skew for incoming expirations
  localtimeOffsetMsec: 0, // Local clock time offset express in a number of milliseconds (positive or negative)
};

export const algorithms = {
  "AES-CTR": { keyBits: 128, ivBits: 128 },
  "AES-CBC": { keyBits: 256, ivBits: 128 },
  "SHA-256": { keyBits: 256 },
} as const;

export type IronAlgorithms = typeof algorithms;

// MAC normalization format version

export const macFormatVersion = "2"; // Prevent comparison of mac values generated with different normalized string formats

export const macPrefix = "Fe26." + macFormatVersion;
