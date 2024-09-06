const Koa = require('koa');
const Router = require('@koa/router');
const { bodyParser } = require('@koa/bodyparser');
const cors = require('@koa/cors');
const { SERVER_PORT, SINGPASS, JWKS } = require('./config');
const { Issuer, generators } = require('openid-client');
const crypto = require('crypto');

/*** 1. Create an OIDC client ***/
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
/*** 2. Create a key-value store
 * This is to store session data between the frontend and the backend.
 * You may also use Cookie or other ways to manage sessions.
 *
 * For demo purpose, we store the session data in this rainbow table 🌈 in memory.
 */
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
/*** 3. Host your JWKS URL ***/
router.get(
  '/.well-known/jwks.json',
  (ctx) => (ctx.body = { keys: [JWKS.PUBLIC_SIG_KEY, JWKS.PUBLIC_ENC_KEY] })
);

/*** 4. Generate a Singpass authorization URL
 * This URL lets the frontend redirect users to the Singpass login page. */
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

/*** 5. Retrieve tokens by auth code
 * Once the frontend received an auth code after user logged in,
 * the frontend passes down the auth code in exchange for either an access_token or user profile.
 *
 * If you need to issue an access_token or an authenticated session
 * to your client app to access your resource servers, this is the place.
 */
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

const server = new Koa();
server.use(cors()).use(bodyParser()).use(router.routes()).listen(SERVER_PORT);
console.log(`Server started at http://localhost:${SERVER_PORT}`);
