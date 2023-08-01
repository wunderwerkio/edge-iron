import { IronAlgorithms } from "./constants.js";

/**
seal() method options.
*/
export interface SealOptionsSub<TAlgo extends keyof IronAlgorithms = keyof IronAlgorithms> {
  /**
  The length of the salt (random buffer used to ensure that two identical objects will generate a different encrypted result). Defaults to 256.
  */
  saltBits: number;

  /**
  The algorithm used. Defaults to 'aes-256-cbc' for encryption and 'sha256' for integrity.
  */
  algorithm: TAlgo;

  /**
  The number of iterations used to derive a key from the password. Defaults to 1.
  */
  iterations: number;

  /**
  Minimum password size. Defaults to 32.
  */
  minPasswordlength: number;
}

/**
generateKey() method options.
*/
export interface GenerateKeyOptions
  extends Pick<
    SealOptionsSub,
    "algorithm" | "iterations" | "minPasswordlength"
  > {
  saltBits?: number;
  salt?: string;
  iv?: Buffer;
}

export interface EncryptionOptions
  extends Omit<GenerateKeyOptions, "algorithm"> {
  algorithm: keyof Omit<IronAlgorithms, "SHA-256">;
}

export interface HMacOptions extends Omit<GenerateKeyOptions, "algorithm"> {
  algorithm: keyof Pick<IronAlgorithms, "SHA-256">;
}

/**
Options for customizing the key derivation algorithm used to generate encryption and integrity verification keys as well as the algorithms and salt sizes used.
*/
export interface SealOptions {
  /**
  Encryption step options.
  */
  encryption: SealOptionsSub<"AES-CBC" | "AES-CTR">;

  /**
  Integrity step options.
  */
  integrity: SealOptionsSub<"SHA-256">;

  /**
  Sealed object lifetime in milliseconds where 0 means forever. Defaults to 0.
   */
  ttl: number;

  /**
  Number of seconds of permitted clock skew for incoming expirations. Defaults to 60 seconds.
  */
  timestampSkewSec: number;

  /**
  Local clock time offset, expressed in number of milliseconds (positive or negative). Defaults to 0.
  */
  localtimeOffsetMsec: number;
}

/**
Generated internal key object.
*/
export interface Key {
  key: Buffer;
  salt: string;
  iv: Buffer;
}

/**
Generated HMAC internal results.
*/
export interface HMacResult {
  digest: string;
  salt: string;
}

/**
Password secret string or buffer.
*/
export type Password = string | Buffer;

export interface PasswordSecret {
  id?: string;
  secret: Password;
}

export interface SpecificPasswordSecret {
  id?: string;
  encryption: Password;
  integrity: Password;
}

export interface PasswordHash {
  [key: string]: Password | PasswordSecret | SpecificPasswordSecret;
}
