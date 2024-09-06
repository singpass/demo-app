const fs = require('fs/promises');
const jose = require('jose');

Promise.all([
  generateKeyPair('ES256').then(makeWrite('Sig')),
  generateKeyPair('ECDH-ES+A256KW').then(makeWrite('Enc')),
]).then(writeJWKS);

function generateKeyPair(alg) {
  return jose.generateKeyPair(alg).then(({ publicKey, privateKey }) => ({
    publicKey: { alg, ...publicKey.export({ format: 'jwk', type: 'spki' }) },
    privateKey: { alg, ...privateKey.export({ format: 'jwk', type: 'sec1' }) },
  }));
}

function makeWrite(suffix) {
  return function writeKeys({ publicKey, privateKey }) {
    return Promise.all([
      fs.writeFile(`public${suffix}`, JSON.stringify(publicKey)),
      fs.writeFile(`private${suffix}`, JSON.stringify(privateKey)),
    ]).then(() => ({ publicKey, privateKey }));
  };
}

function writeJWKS([signKeys, encryptKeys]) {
  const signPublicKey = {
    ...signKeys.publicKey,
    use: 'sig',
    kid: 'my-sig-key',
  };
  const encryptPublicKey = {
    ...encryptKeys.publicKey,
    use: 'enc',
    kid: 'my-enc-key',
  };
  return fs.writeFile(
    'jwks.json',
    JSON.stringify({ keys: [signPublicKey, encryptPublicKey] })
  );
}
