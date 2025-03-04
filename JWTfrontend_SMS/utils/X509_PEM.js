const nodeForge = require("node-forge");
const axios = require("axios");

const getPubkeyFromV1Certs = async (jwt) => {
  // 从JWT中提取 kid
  const header = JSON.parse(atob(jwt.split(".")[0]));
  const kid = header.kid;

  // 获取v1/certs的数据
  const response = await axios.get("https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com");

  const certs = response.data;

  // 找到对应kid的证书
  const pemCert = certs[kid];
  if (!pemCert) {
    throw new Error(`Certificate with kid ${kid} not found`);
  }

  // 从PEM格式中提取公钥
  const pubKeyData = nodeForge.pki.certificateFromPem(pemCert).publicKey;
  const modulus = BigInt(pubKeyData.n.toString());

  console.log("Modulus:", modulus); // 输出模数

  return modulus;
};

module.exports = { getPubkeyFromV1Certs };