import config from './config.mjs';
import { Issuer, generators } from 'openid-client';
import * as crypto from 'crypto';
import Router from '@koa/router';

// This demo uses panva/node-openid-client, an off-the-shelf OIDC client.

const singpassIssuer = await Issuer.discover(config.ISSUER_URL);

const singpassClient = new singpassIssuer.Client(
  {
    client_id: config.CLIENT_ID,
    response_types: ['code'],
    token_endpoint_auth_method: 'private_key_jwt',
    id_token_signed_response_alg: config.KEYS.PRIVATE_SIG_KEY.alg,
  },
  { keys: [config.KEYS.PRIVATE_SIG_KEY, config.KEYS.PRIVATE_ENC_KEY] }
);

// This demo uses Koa for routing.

const router = new Router();

router.get('/.well-known/jwks.json', function getJwks(ctx) {
  ctx.body = { keys: [config.KEYS.PUBLIC_SIG_KEY, config.KEYS.PUBLIC_ENC_KEY] };
});

router.get('/login', async function handleLogin(ctx) {
  const code_verifier = generators.codeVerifier();
  const code_challenge = generators.codeChallenge(code_verifier);
  const nonce = crypto.randomUUID();
  const state = crypto.randomBytes(16).toString('hex');
  ctx.session.auth = { code_verifier, nonce, state };
  const authorizationUrl = singpassClient.authorizationUrl({
    redirect_uri: config.REDIRECT_URI,
    code_challenge_method: 'S256',
    code_challenge,
    nonce,
    state,
  });
  ctx.redirect(authorizationUrl);
});

router.get('/callback', async function handleSingpassCallback(ctx) {
  try {
    const receivedQueryParams = ctx.request.query;
    const { code_verifier, nonce, state } = ctx.session.auth;
    const tokenSet = await singpassClient.callback(config.REDIRECT_URI, receivedQueryParams, { code_verifier, nonce, state });
    ctx.session.auth = tokenSet;
    ctx.session.user = { id: tokenSet.claims().sub };
    ctx.redirect('/');
    console.log('These are the claims in the ID token:');
    console.log(tokenSet.claims(), '\n');
  } catch {
    ctx.status = 401;
  }
});

router.get('/user', function getUser(ctx) {
  if (ctx.session.user) {
    ctx.body = { id: ctx.session.user.id };
  } else {
    ctx.status = 401;
  }
});

router.get('/logout', function handleLogout(ctx) {
  ctx.session = null;
  ctx.redirect('/');
});

export { router };
