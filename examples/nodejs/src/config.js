/** IMPORTANT NOTE:
 * DO NOT hardcode private keys in your code.
 * Private keys are secrets. Store private keys in a safe place (Ex: SecretsManager, Vault, ...).
 * The below private keys are hardcoded here for the convenience of the demo.
 */
module.exports = {
  SERVER_PORT: 5081,
  JWKS: {
    PRIVATE_SIG_KEY: {
      alg: 'ES256',
      kty: 'EC',
      x: 'tqG7PiAPD0xTBKdxDd4t8xAjJleP3Szw1CZiBjogmoc',
      y: '256TjvubWV-x-C8lptl7eSbMa7pQUXH9LY1AIHUGINk',
      crv: 'P-256',
      d: 'PgL1UKVpvg_GeKdxV-oUEPIDhGBP2YYZLGiZ5HXDZDI',
      kid: 'my-sig-key',
    },
    PRIVATE_ENC_KEY: {
      alg: 'ECDH-ES+A256KW',
      kty: 'EC',
      x: '_TSrfW3arG1Ebc8pCyT-r5lAFvCh_rJvC5HD5-y8yvs',
      y: 'Sr2vpuU6gzdUiXddGnRJIroXCfdameaR1mgU49H5h9A',
      crv: 'P-256',
      d: 'AEabUwi3VjOOfiyoOtSGrqpl8cfhcUhNtj-xh1l-UYE',
      kid: 'my-enc-key',
    },
    PUBLIC_SIG_KEY: {
      alg: 'ES256',
      kty: 'EC',
      x: 'tqG7PiAPD0xTBKdxDd4t8xAjJleP3Szw1CZiBjogmoc',
      y: '256TjvubWV-x-C8lptl7eSbMa7pQUXH9LY1AIHUGINk',
      crv: 'P-256',
      use: 'sig',
      kid: 'my-sig-key',
    },
    PUBLIC_ENC_KEY: {
      alg: 'ECDH-ES+A256KW',
      kty: 'EC',
      x: '_TSrfW3arG1Ebc8pCyT-r5lAFvCh_rJvC5HD5-y8yvs',
      y: 'Sr2vpuU6gzdUiXddGnRJIroXCfdameaR1mgU49H5h9A',
      crv: 'P-256',
      use: 'enc',
      kid: 'my-enc-key',
    },
  },
  SINGPASS: {
    CLIENT_ID: 'dcxjBqMGNQ7QLHEnfEBitKUxGtW2S8y0',
    ISSUER_URL: 'https://stg-id.singpass.gov.sg',
    REDIRECT_URI: 'http://localhost:3080/callback',
    AMR: 'pwd',
  },
};
