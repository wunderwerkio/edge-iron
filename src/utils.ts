import { Buffer } from "buffer";

export const base64UrlEncode = (buffer: Buffer) => {
  return buffer
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/\=/g, "");
};

export const base64UrlDecode = (value: string) => {
  if (!/^[\w\-]*$/.test(value)) {
    throw new Error("Invalid character");
  }

  return Buffer.from(value, "base64");
};
