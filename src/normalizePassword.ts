import { Password, PasswordSecret, SpecificPasswordSecret } from "./types.js";

export const normalizePassword = (
  password: Password | PasswordSecret | SpecificPasswordSecret
) => {
  if (password && typeof password === "object" && !Buffer.isBuffer(password)) {
    return {
      id: password.id,
      encryption: "secret" in password ? password.secret : password.encryption,
      integrity: "secret" in password ? password.secret : password.integrity,
    };
  }

  return {
    encryption: password,
    integrity: password,
  };
};
