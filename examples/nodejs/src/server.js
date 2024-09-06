const Koa = require('koa');
const Router = require('@koa/router');
const { bodyParser } = require('@koa/bodyparser');
const cors = require('@koa/cors');
const { SERVER_PORT, SINGPASS, JWKS } = require('./config');
const { Issuer, generators } = require('openid-client');
const crypto = require('crypto');

const getSingpassOidcClient = Issuer.discover(SINGPASS.ISSUER_URL).then(
  (issuer) =>
    new issuer.Client(
      {
        client_id: SINGPASS.CLIENT_ID,
        response_types: ['code'],
        token_endpoint_auth_method: 'private_key_jwt',
        id_token_signed_response_alg: JWKS.PRIVATE_SIG_KEY.alg,
      },
      { keys: [JWKS.PRIVATE_SIG_KEY] }
    )
);
const rainbowTable = (function makeRainbowTable() {
  const table = new Map();

  function getRandoms(code_challenge) {
    const cache = table.get(code_challenge);
    table.delete(code_challenge);
    return cache;
  }

  function generateRandoms() {
    const code_verifier = generators.codeVerifier();
    const code_challenge = generators.codeChallenge(code_verifier);
    const nonce = crypto.randomUUID();
    const state = crypto.randomBytes(16).toString('hex');
    table.set(code_challenge, { code_verifier, nonce, state });
    return { code_challenge, nonce, state };
  }
  return { generateRandoms, getRandoms };
})();

const router = new Router();
router.get(
  '/.well-known/jwks.json',
  (ctx) => (ctx.body = { keys: [JWKS.PUBLIC_SIG_KEY, JWKS.PUBLIC_ENC_KEY] })
);
router.post('/auth/claims', async function (ctx) {
  const client = await getSingpassOidcClient;
  const { code_challenge, ...params } = ctx.request.body;
  const checks = rainbowTable.getRandoms(code_challenge);
  const tokenSet = await client.callback(SINGPASS.REDIRECT_URI, params, checks);
  /** DO NOT log tokenSet in your app.
   * Tokens are users' secrets. If tokens are logged,
   * internal attackers (whoever has access to the log) can hijack users' sessions.*/
  // console.log(tokenSet);

  const claims = tokenSet.claims();

  // Additional checks
  if (SINGPASS.CLIENT_ID !== claims.aud || SINGPASS.AMR !== claims.amr.join()) {
    return (ctx.status = 401);
  }

  ctx.body = claims;
});
router.get('/auth/authorization', async function (ctx) {
  const client = await getSingpassOidcClient;
  ctx.body = {
    url: client.authorizationUrl({
      redirect_uri: SINGPASS.REDIRECT_URI,
      code_challenge_method: 'S256',
      ...rainbowTable.generateRandoms(),
    }),
  };
});

const server = new Koa();
server.use(cors()).use(bodyParser()).use(router.routes()).listen(SERVER_PORT);
console.log(`Server started at http://localhost:${SERVER_PORT}`);
