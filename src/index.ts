import crypto from "crypto";
import base32 from "hi-base32";

/**
 * @digest {options}
 */

export const digest = (options: any) => {
  //unpack options
  let secret = options.secret;
  let counter = options.counter;
  let encoding = options.encoding || 'ascii';
  let algorithm = (options.algorithm || 'sha1').toLowerCase();

  //secret key buffer size.
  let _secret_buffer_size;

  //convert secret to Buffer...
  if(!Buffer.isBuffer(secret)){
    if (encoding === 'base32') { 
      secret = base32.decode(secret); 
    }
    else {
      secret = Buffer.from(secret, encoding)
    }
  }
  switch (algorithm) {
    case 'sha1':
      _secret_buffer_size = 20; // 20bytes
      break;
    case 'sha256':
      _secret_buffer_size = 32; // 32bytes
      break;
    case 'sha512':
      _secret_buffer_size =  64; // 64bytes
      break;
    default:
      console.warn('given algorithm doesn\'t support by this package.')
      break;
  }
  
  // map the secret to be a fixed number of bytes for the one-time password to be calculated correctly.

  if(_secret_buffer_size && _secret_buffer_size !== secret.length){
    secret = Buffer.from(Array(Math.ceil(_secret_buffer_size / secret.length) + 1).join(secret.toString('hex')),'hex').subarray(0, _secret_buffer_size);
  }

  //create a buffer from the counter
  let bufferSize = Buffer.alloc(8);
  let tmp = counter;

  for (let i = 0; i < 8; i++) {
    //mask 0xff over number to get last 8
    bufferSize[7 - i] = tmp & 0xff;
    // shift 8 and get ready to loop over the next batch of 8
    tmp = tmp >> 8;
  }
  
  const hmac = crypto.createHmac(algorithm, secret);
  //update {hmac} with counter value.
  hmac.update(bufferSize);

  return hmac.digest();
};

/**
 * @counter {fn}
 */

export const _counter = (options: any) => {
   let step = options.step || 30;
   let time = options.time != null ? (options.time * 1000) : Date.now(); // current time frame 
   let initial_time = (options.epoch != null ? (options.epoch * 1000) : (options.initial_time * 1000)) || 0;
   //Option:2
    //  const currentTime = Date.now(); // get current-time
    //  const timeStep = 30 * 1000; // convert time-step or interval into miliseconds.
    //  const counter = Math.floor((currentTime - 0) / timeStep); // calculate counter for totp ex: 30seconds.
   return Math.floor((time - initial_time) / step / 1000)
}

/**
 * @generateSecretASCII
 * @params {integer}{length} the length of the key.
 * @params {symbols}
 * @return {string} the generated key.
 */

export const generateSecretASCII = (length: number, symbols:boolean) => {
    const bytes = crypto.randomBytes(length || 32);
    let set = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz';
    let output = '';

    //set symbols to output
    if(symbols){
      set += '!@#$%^&*()<>?/[]{},.:;';
    }

    for (const byte of bytes) {
      output += set[Math.floor(byte / 255.0 * (set.length - 1))];
    }
    
    return output;
}



export const generateHOTP = (options:any) => {
  //verify options for secret & counter.
  let secret = options.secret;
  let counter = options.counter;

  if(secret === null || typeof secret === 'undefined'){
       throw new Error('missing hotp secret')
  }

  if(counter === null || typeof counter === 'undefined'){
     throw new Error('missing hotp-counter')
  }

  //length of hotp
  let digits = (options.digits !=null ? options.digits : options.length) || 6;

  let hmacResult = digest(options)
  // Step 2: Generate a 4-byte string (Dynamic Truncation)
  // compute HOTP offset
  // First we take the last byte of our generated HMAC and extract last 4 bits out of it.
  // This will be our {offset}, a number between 0 and 15.
   let offset = hmacResult[hmacResult.length - 1] & 0xf;
  
  // Next we take 4 bytes out of the HMAC, starting at the offset
  // calculate binary code (RFC4226 5.4)
  let code = (hmacResult[offset] & 0x7f) << 24 |
             (hmacResult[offset + 1] & 0xff) << 16 |
             (hmacResult[offset + 2] & 0xff) << 8 |
             (hmacResult[offset + 3] & 0xff);

  
  return code % 10 ** digits; //finalOTP = (truncatedHash % (10 ^ numberOfDigitsRequiredInOTP));
}

/**
 * Generate TOTP
 * 
 */
export const generateTOTP = (options:any) => {
    //create shadow options...
    options = Object.create(options)

    //verify secret exists
    if(options.secret === null || typeof options.secret === 'undefined'){
      throw new Error('secret is missing.')
    }

    //calculate default counter value
    if(options.counter == null) options.counter = _counter(options)

    return generateHOTP(options);

}

/**
 * Verify HOTP
 * 
 */

export const verifyHOTP = (options:any) => {
  // shadow options
  options = Object.create(options);

  // verify secret and token exist
  let secret = options.secret;
  let token = options.token;
  if (secret === null || typeof secret === 'undefined') throw new Error('Speakeasy - hotp.verifyDelta - Missing secret');
  if (token === null || typeof token === 'undefined') throw new Error('Speakeasy - hotp.verifyDelta - Missing token');

  // unpack options
   token = String(options.token);
  let digits = parseInt(options.digits, 10) || 6;
  let window = parseInt(options.window, 10) || 0;
  let counter = parseInt(options.counter, 10) || 0;

  // fail if token is not of correct length
  if (token.length !== digits) {
    return;
  }

  // parse token to integer
  token = parseInt(token, 10);

  // fail if token is NA
  if (isNaN(token)) {
    return;
  }

   // loop from C to C + W inclusive
   for (let i = counter; i <= counter + window; ++i) {
    options.counter = i;
    // domain-specific constant-time comparison for integer codes
    if (parseInt(exports.generateHOTP(options), 10) === token) {
      console.log('matching', generateHOTP(options), token);
      
      // found a matching code, return delta
      return {delta: i - counter};
    }
  }

}

/**
 * Verify TOTP
 * 
 */

export const verifyOTP = (options:any) => {
   // shadow options
   options = Object.create(options);
   //verify secret and token exist
   let secret = options.secret;
   let token = options.token;


   if(secret === null || typeof secret === 'undefined') throw new Error('missing secret')
   if(token === null || typeof token === 'undefined') throw new Error('missing token')

   //unpack options
   let window = parseInt(options.window, 10) || 0;

   //calculate default counter value
   if(options.counter == null) options.counter = _counter(options);

   //adjust for two-sided window
   options.counter -= window
   options.window  += window
   let delta = verifyHOTP(options)
   if (delta) {
    delta.delta -= window;
  }
  console.log(delta)
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
  const key = generateSecretASCII(length, symbols)

  const secretKey:any = {
     ascii: key,
     hex: Buffer.from(key, 'ascii').toString('hex'),
     base32: base32.encode(Buffer.from(key)).toString().replace(/=/g, '')
  }
  return secretKey;
};

const secret = generateSecret({ length: 20 });
const token = generateTOTP({
  secret: secret.base32,
  encoding: 'base32',
})

// Verify a given token
var tokenValidates = verifyOTP({
  secret: secret.base32,
  encoding: 'base32',
  token: token,
  window: 1
});
// console.log(secret, token);
