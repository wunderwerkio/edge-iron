import { Buffer } from "buffer";
import Bourne from "@hapi/bourne";
import { timingSafeEqual }  from "./crypto/index.js";
import { hmacWithPassword } from "./hmacWithPassword.js";
import { normalizePassword } from "./normalizePassword.js";
import {
  Password,
  PasswordHash,
  PasswordSecret,
  SealOptions,
  SpecificPasswordSecret,
} from "./types.js";
import { base64UrlDecode } from "./utils.js";
import { decrypt } from "./decrypt.js";
import { macPrefix } from "./constants.js";

/**
 * Verifies, decrypts, and reconstruct an iron protocol string into an object.
 */
export const unseal = async <T>(
  sealed: string,
  password: Password | PasswordHash,
  options?: SealOptions
): Promise<T> => {
  options = Object.assign({}, options); // Shallow cloned to prevent changes during async operations

  const now = Date.now() + (options.localtimeOffsetMsec ?? 0); // Measure now before any other processing

  // Break string into components

  const parts = sealed.split("*");
  if (parts.length !== 8) {
    throw new Error("Incorrect number of sealed components");
  }

  const sealedMacPrefix = parts[0];
  const passwordId = parts[1];
  const encryptionSalt = parts[2];
  const encryptionIv = parts[3];
  const encryptedB64 = parts[4];
  const expiration = parts[5];
  const hmacSalt = parts[6];
  const hmac = parts[7];
  const macBaseString =
    sealedMacPrefix +
    "*" +
    passwordId +
    "*" +
    encryptionSalt +
    "*" +
    encryptionIv +
    "*" +
    encryptedB64 +
    "*" +
    expiration;

  // Check prefix

  if (sealedMacPrefix !== macPrefix) {
    throw new Error("Wrong mac prefix");
  }

  // Check expiration

  if (expiration) {
    if (!expiration.match(/^\d+$/)) {
      throw new Error("Invalid expiration");
    }

    const exp = parseInt(expiration, 10);
    if (exp <= now - options.timestampSkewSec * 1000) {
      throw new Error("Expired seal");
    }
  }

  // Obtain password

  let actualPassword: Password | PasswordSecret | SpecificPasswordSecret = "";
  if (!password) {
    throw new Error("Empty password");
  }

  if (typeof password === "object" && !Buffer.isBuffer(password)) {
    actualPassword = password[passwordId || "default"];
    if (!password) {
      throw new Error("Cannot find password: " + passwordId);
    }
  }
  else {
    actualPassword = password;
  }

  actualPassword = normalizePassword(actualPassword);

  // Check hmac

  const macOptions = Object.assign({}, options.integrity);
  macOptions.salt = hmacSalt;

  const mac = await hmacWithPassword(
    actualPassword.integrity,
    macOptions,
    macBaseString
  );

  if (!timingSafeEqual(Buffer.from(mac.digest), Buffer.from(hmac))) {
    throw new Error("Bad hmac value");
  }

  // Decrypt

  const encrypted = base64UrlDecode(encryptedB64);

  const decryptOptions = Object.assign({}, options.encryption);
  decryptOptions.salt = encryptionSalt;

  decryptOptions.iv = base64UrlDecode(encryptionIv);

  const decrypted = await decrypt(
    actualPassword.encryption,
    decryptOptions,
    encrypted
  );

  // Parse JSON

  try {
    return Bourne.parse(decrypted);
  } catch (err) {
    throw new Error(
      "Failed parsing sealed object JSON: " + (err as Error)?.message
    );
  }
};
