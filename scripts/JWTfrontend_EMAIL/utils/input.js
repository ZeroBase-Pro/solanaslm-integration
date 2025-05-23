const {writeFile} = require("fs/promises");
const assert = require("assert");
const {findClaimLocation} = require("./claim_loc.js");
const {getPubkeyFromV1Certs} = require("./X509_PEM.js");
const {MAX_NONCE_BYTES, MAX_EMAIL_BYTES, MAX_EMAIL_VERIFIED_BYTES } = require("./constants.js");
const CryptoJS = require('crypto');


const CIRCOM_BIGINT_N = 121;
const CIRCOM_BIGINT_K = 17;
const MAX_MSG_PADDED_BYTES = 1024;

const atob = require('atob');

const generate_data = (jwtToken) => {
  // spilt JWT: header, payload, signature
  const [header, payload, signature] = jwtToken.split('.');

  // decode payload
  const decodedPayload = JSON.parse(atob(payload));

  // extract claims
  const data = {
    jwt: `${header}.${payload}`,
    sig: signature,
    nonce: decodedPayload.authNonce,
    email: decodedPayload.email,
    email_verified: decodedPayload.email_verified,
  };
  return data;
}

const toCircomBigIntBytes = (num) => {
  const res = [];
  const bigintNum = typeof num == "bigint" ? num : num.valueOf();
  const msk = (1n << BigInt(CIRCOM_BIGINT_N)) - 1n;

  for (let i = 0; i < CIRCOM_BIGINT_K; ++i) {
    res.push(((bigintNum >> BigInt(i * CIRCOM_BIGINT_N)) & msk).toString());
  }
  
  return res;
}

const mergeUInt8Arrays = (a1, a2) => {
  var mergedArray = new Uint8Array(a1.length + a2.length);
  mergedArray.set(a1);
  mergedArray.set(a2, a1.length);
  
  return mergedArray;
}

const int8toBytes = (num) => {
  const arr = new ArrayBuffer(1);
  const view = new DataView(arr);
  view.setUint8(0, num);

  return new Uint8Array(arr);
}

// https://github.com/zkemail/zk-email-verify/blob/main/packages/helpers/src/binary-format.ts
// Works only on 32 bit sha text lengths
const int64toBytes = (num) => {
  const arr = new ArrayBuffer(8); // an Int32 takes 4 bytes
  const view = new DataView(arr);
  view.setInt32(4, num, false); // byteOffset = 0; litteEndian = false
  return new Uint8Array(arr);
}

const Uint8ArrayToCharArray = (a) => {
  return Array.from(a).map((x) => x.toString());
}

// Puts an end selector, a bunch of 0s, then the length, then fill the rest with 0s.
const sha256Pad = async (prehash_prepad_m, maxShaBytes) => {
  const length_bits = prehash_prepad_m.length * 8; // bytes to bits
  const length_in_bytes = int64toBytes(length_bits);

  prehash_prepad_m = mergeUInt8Arrays(prehash_prepad_m, int8toBytes(2 ** 7));
  while ((prehash_prepad_m.length * 8 + length_in_bytes.length * 8) % 512 !== 0) {
    prehash_prepad_m = mergeUInt8Arrays(prehash_prepad_m, int8toBytes(0));
  }
  prehash_prepad_m = mergeUInt8Arrays(prehash_prepad_m, length_in_bytes);
  assert(
    (prehash_prepad_m.length * 8) % 512 === 0,
    "Padding did not compconste properly!"
  );

  const messageLen = prehash_prepad_m.length;
  while (prehash_prepad_m.length < maxShaBytes) {
    prehash_prepad_m = mergeUInt8Arrays(prehash_prepad_m, int64toBytes(0));
  }

  console.log(prehash_prepad_m.length, maxShaBytes);
  assert(
    prehash_prepad_m.length === maxShaBytes,
    "Padding to max length did not compconste properly!"
  );

  return [prehash_prepad_m, messageLen];
}

const splitJWT = (jwt) => {
  const result = [];
  let i = 0;

  while (jwt.length) {
    i++;
    const chunk = jwt.splice(0, 16);
    result.push(chunk);
  }

  return result
}
const uint8ToBits = (uint8) => {
  return uint8.reduce((acc, byte) => acc + byte.toString(2).padStart(8, '0'), '');
}

const shaHash = (str) => {
  return CryptoJS.createHash('sha256').update(str).digest();
}

const createInputs = async (data, highpartPK, lowpartPK, exp, project_id) => {
  const msg = data.jwt;
  const sig = data.sig;
  const signature = toCircomBigIntBytes(BigInt(`0x${Buffer.from(sig, "base64").toString("hex")}`));
  const [jwtPadded, _] = await sha256Pad(new TextEncoder().encode(msg), MAX_MSG_PADDED_BYTES);
  const jwt = await Uint8ArrayToCharArray(jwtPadded); 
  const jwt_sha256 = uint8ToBits(shaHash(new TextEncoder().encode(msg)));
  const nonceClaim = findClaimLocation(data.jwt, data.nonce, MAX_NONCE_BYTES);
  const emailClaim = findClaimLocation(data.jwt, data.email, MAX_EMAIL_BYTES);
  const email_verifiedClaim = findClaimLocation(data.jwt, data.email_verified, MAX_EMAIL_VERIFIED_BYTES);
  const rsaPubkey = toCircomBigIntBytes(await getPubkeyFromV1Certs(data.jwt));

  const inputs = {
    jwt_segments: splitJWT(jwt),
    jwt_sha256:jwt_sha256.split(''),
    nonce: nonceClaim[0],
    nonce_loc: nonceClaim[1],
    email: emailClaim[0],
    email_loc: emailClaim[1],
    email_verified: email_verifiedClaim[0],
    email_verified_loc: email_verifiedClaim[1],
    highpartPK: highpartPK.toString(),
    lowpartPK: lowpartPK.toString(),
    exp: BigInt(exp).toString(),
    project_id: BigInt(project_id).toString(),
    signature,
    modulus: rsaPubkey,
  }

  const jwt_length = msg.length;
  

  await writeFile(
    `${__dirname}/../inputs/ZKLogin_solana_EMAIL.json`,
    JSON.stringify(inputs, null, 2),
  )
}

module.exports = {
  createInputs,
  generate_data,
  toCircomBigIntBytes,
};