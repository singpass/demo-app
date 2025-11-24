import config from './config.mjs';
import { Issuer, generators, custom } from 'openid-client';
import * as crypto from 'crypto';
import Router from '@koa/router';

// This demo uses panva/node-openid-client, an off-the-shelf OIDC client library.

let singpassClient;
await initializeSingpassClient();

/**
 * Initializes the Singpass OIDC client. This is mostly done automatically, based on Singpass' OpenID Provider config,
 * which can be retrieved as a JSON document from `<issuer_url>/.well-known/openid-configuration`, but some manual
 * configuration is necessary depending on the client library you're using.
 */
async function initializeSingpassClient() {
  try {
    const singpassIssuer = await Issuer.discover(config.ISSUER_URL);
    singpassClient = new singpassIssuer.Client(
      {
        client_id: config.CLIENT_ID,
        // This OIDC client library requires that you manually configure its behaviour via the options below.
        // Please refer to Singpass' OpenID Provider config, which specifies the supported values for each field, or
        // to https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata, for info about each field.
        // For most fields, Singpass supports just one valid value, so you likely won't have to change this very much.
        response_types: ['code'],
        token_endpoint_auth_method: 'private_key_jwt',
        id_token_signed_response_alg: 'ES256',
        // The following options should be included if and only if your app is a Myinfo app.
        userinfo_encrypted_response_alg: config.KEYS.PRIVATE_ENC_KEY.alg,
        userinfo_encrypted_response_enc: 'A256GCM',
        userinfo_signed_response_alg: 'ES256',
        // The following options should be included if and only if your app is configured (in the Singpass Developer
        // Portal) to receive encrypted ID token responses (i.e. your app's client profile is 'direct_pii_allowed').
        // id_token_encrypted_response_alg: config.KEYS.PRIVATE_ENC_KEY.alg,
        // id_token_encrypted_response_enc: 'A256CBC-HS512',
      },
      {
        keys: [config.KEYS.PRIVATE_SIG_KEY, config.KEYS.PRIVATE_ENC_KEY],
      }
    );
  } catch (error) {
    console.error('Failed to initialize Singpass client', error);
  }
}

// To keep your Singpass OIDC client up-to-date with any changes to Singpass' OIDC config, we recommend reinitializing
// it periodically (an hour or more apart). This pulls the latest OIDC config and updates the client accordingly.
const ONE_HOUR_IN_MS = 60 * 60 * 1000;
setInterval(initializeSingpassClient, ONE_HOUR_IN_MS);

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

  // Authorization request
  const authorizationUrl = singpassClient.authorizationUrl({
    redirect_uri: config.REDIRECT_URI,
    code_challenge_method: 'S256',
    code_challenge,
    nonce,
    state,
    scope: config.SCOPES,
  });
  ctx.redirect(authorizationUrl);
});

router.get('/callback', async function handleSingpassCallback(ctx) {
  try {
    const receivedQueryParams = ctx.request.query;
    const { code_verifier, nonce, state } = ctx.session.auth;

    // Token request
    const tokenSet = await singpassClient.callback(config.REDIRECT_URI, receivedQueryParams, {
      code_verifier,
      nonce,
      state,
    });
    console.log('These are the claims in the ID token:');
    console.log(tokenSet.claims());

    // Userinfo request (this is only necessary if your app is a Myinfo app)
    const userInfo = await singpassClient.userinfo(tokenSet);
    console.log('This is the user info returned:');
    console.log(userInfo);

    ctx.session.user = { ...tokenSet.claims(), ...userInfo };
    ctx.redirect('/');
  } catch (err) {
    console.error(err);
    ctx.status = 401;
  }
});

router.get('/user', function getUser(ctx) {
  if (ctx.session.user) {
    ctx.body = ctx.session.user;
  } else {
    ctx.status = 401;
  }
});

router.get('/logout', function handleLogout(ctx) {
  ctx.session = null;
  ctx.redirect('/');
});

export { router };
