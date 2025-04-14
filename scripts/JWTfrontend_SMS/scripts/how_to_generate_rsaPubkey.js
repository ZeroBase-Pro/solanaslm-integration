const {getPubkeyFromV1Certs} = require("../utils/X509_PEM.js");
const {toCircomBigIntBytes} = require("../utils/input.js");

const jwtToken = ""

const [header, payload, _] = jwtToken.split('.');

const header_payload = `${header}.${payload}`
// get rsaPubkey in circomBigIntBytes format
const rsaPubkey = toCircomBigIntBytes(await getPubkeyFromV1Certs(header_payload));