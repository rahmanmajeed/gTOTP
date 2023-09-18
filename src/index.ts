import crypto from "crypto";
import base32 from "hi-base32";

/**
 * @digest {options}
 */

export const digest = (options: any) => {
  //unpack options
  let secret = options.secret;
};

/**
 * @generateSecretASCII
 * @params {integer}{length} the length of the key.
 * @params {symbols}
 * @return {string} the generated key.
 */

export const generateSecretASCII = (length: number, symbols:boolean) => {
    const bytes = crypto.randomBytes(length || 32);
    var set = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz';
    let output = '';

    // for (let i = 0; i < bytes.length; i++) {
    //   output += set[Math.floor(bytes[i] / 255.0 * (set.length - 1))];
    // }
    for (const byte of bytes) {
      output += set[Math.floor(byte / 255.0 * (set.length - 1))];
    }
    let temp = Math.floor(bytes[0])
    let ouput= temp /255
    return {bytes, temp, ouput,  output};
}

/**
 * @generate {secret}
 * @params {options}
 * @return {secret}
 */

export const generateSecret = (options: any) => {
  //options

  if (!options) options = {};
  let length = options.length || 32;
  let name = options.name || "SecretKey";
  let symbols = true;

  // turn off symbols only when explicity told to.
  if (options.symbols !== undefined && options.symbols === false) {
    symbols = false;
  }

  //generate base32 secret...
  const secretKey = generateSecretASCII(length, symbols)
  console.log(base32.encode(Buffer.from(secretKey.output)).toString().replace(/=/g, ''));
  const buf = crypto.randomBytes(length);
  return base32.encode(buf).replace(/=/g, "");
};

console.log(generateSecret({ length: 20 }));
