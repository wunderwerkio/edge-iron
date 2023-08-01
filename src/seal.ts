import { encrypt } from "./encrypt.js";
import { hmacWithPassword } from "./hmacWithPassword.js";
import { normalizePassword } from "./normalizePassword.js";
import {
  Password,
  PasswordSecret,
  SealOptions,
  SpecificPasswordSecret,
} from "./types.js";
import { base64UrlEncode } from "./utils.js";

export const seal = async (
  object: any,
  password: Password | PasswordSecret | SpecificPasswordSecret,
  options: SealOptions
): Promise<string> => {
  options = Object.assign({}, options);

  const now = Date.now() + (options.localtimeOffsetMsec ?? 0);

  // Serialize object.
  const objectString = JSON.stringify(object);

  // Obtain password.
  let passwordId = "";
  password = normalizePassword(password);
  if (password.id) {
    if (!/^\w+$/.test(password.id)) {
      throw Error("Invalid password id");
    }

    passwordId = password.id;
  }

  // Encrypt object string.
  const { encrypted, key } = await encrypt(
    password.encryption,
    options.encryption,
    objectString
  );

  // Encode data.
  const encryptedB64 = base64UrlEncode(encrypted);
  const iv = base64UrlEncode(key.iv);
  const expiration = options.ttl ? now + options.ttl : "";
  const macBaseString =
    exports.macPrefix +
    "*" +
    passwordId +
    "*" +
    key.salt +
    "*" +
    iv +
    "*" +
    encryptedB64 +
    "*" +
    expiration;

  // Compute MAC.
  const mac = await hmacWithPassword(
    password.integrity,
    options.integrity,
    macBaseString
  );

  // Put it all together

  // prefix*[password-id]*encryption-salt*encryption-iv*encrypted*[expiration]*hmac-salt*hmac
  // Allowed URI query name/value characters: *-. \d \w

  const sealed = macBaseString + "*" + mac.salt + "*" + mac.digest;
  return sealed;
};
