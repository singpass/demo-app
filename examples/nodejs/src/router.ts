import config from '../../config.json';
import * as openidClient from 'openid-client';
import Router from '@koa/router';

// This demo uses panva/openid-client, an off-the-shelf OIDC client library.

// Keys imported using crypto.subtle.importKey do not retain the 'kid' nor 'alg' properties, but both are needed
// for this OIDC client library (e.g. to pick the correct decryption key to use), so we provide them here

const privateSigningKey = {
  kid: config.KEYS.PRIVATE_SIG_KEY.kid,
  alg: config.KEYS.PRIVATE_SIG_KEY.alg,
  key: await crypto.subtle.importKey(
    'jwk',
    config.KEYS.PRIVATE_SIG_KEY,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign']
  ),
};

const privateEncryptionKey = {
  kid: config.KEYS.PRIVATE_ENC_KEY.kid,
  alg: config.KEYS.PRIVATE_ENC_KEY.alg,
  key: await crypto.subtle.importKey('jwk', config.KEYS.PRIVATE_ENC_KEY, { name: 'ECDH', namedCurve: 'P-256' }, false, [
    'deriveKey',
    'deriveBits',
  ]),
};

let singpassConfig: openidClient.Configuration;
await initializeSingpassConfig();

/**
 * Initializes the Singpass OIDC client. This is mostly done automatically, based on Singpass' OpenID Provider config,
 * which can be retrieved as a JSON document from `<issuer_url>/.well-known/openid-configuration`, but some manual
 * configuration is necessary depending on the client library you're using.
 */
async function initializeSingpassConfig() {
  try {
    singpassConfig = await openidClient.discovery(
      new URL(config.ISSUER_URL),
      config.CLIENT_ID,
      undefined,
      openidClient.PrivateKeyJwt(privateSigningKey)
    );
    openidClient.enableDecryptingResponses(
      singpassConfig,
      [
        'A256GCM', //       encrypted userinfo responses are encrypted using this algorithm
        'A256CBC-HS512', // encrypted ID token responses are encrypted using this algorithm
      ],
      privateEncryptionKey
    );
  } catch (error) {
    console.error('Failed to initialize Singpass config', error);
  }
}

// To keep your Singpass OIDC client up-to-date with any changes to Singpass' OIDC config, we recommend reinitializing
// it periodically (an hour or more apart). This pulls the latest OIDC config and updates the client accordingly.
const ONE_HOUR_IN_MS = 60 * 60 * 1000;
setInterval(initializeSingpassConfig, ONE_HOUR_IN_MS);

// This demo uses Koa for routing.

const router = new Router();

router.get('/.well-known/jwks.json', function getJwks(ctx) {
  ctx.body = { keys: [config.KEYS.PUBLIC_SIG_KEY, config.KEYS.PUBLIC_ENC_KEY] };
});

router.get('/login', async function handleLogin(ctx) {
  const code_verifier = openidClient.randomPKCECodeVerifier();
  const code_challenge = await openidClient.calculatePKCECodeChallenge(code_verifier);
  const nonce = openidClient.randomNonce();
  const state = openidClient.randomState();
  ctx.session.auth = { code_verifier, nonce, state };

  // Authorization request
  const redirectTo = openidClient.buildAuthorizationUrl(singpassConfig, {
    redirect_uri: config.REDIRECT_URI,
    code_challenge_method: 'S256',
    code_challenge,
    nonce,
    state,
    scope: config.SCOPES,
  });
  ctx.redirect(redirectTo.href);
});

router.get('/callback', async function handleSingpassCallback(ctx) {
  try {
    const currentUrl = new URL(ctx.request.href);
    const { code_verifier, nonce, state } = ctx.session.auth;

    // Token request
    const tokens = await openidClient.authorizationCodeGrant(singpassConfig, currentUrl, {
      pkceCodeVerifier: code_verifier,
      expectedNonce: nonce,
      expectedState: state,
      idTokenExpected: true,
    });
    const idTokenClaims = tokens.claims();
    console.log('These are the claims in the ID token:');
    console.log(idTokenClaims);

    if (idTokenClaims === undefined) {
      throw new Error('ID token claims are undefined');
    }

    // Userinfo request (this is only necessary if your app is a Myinfo app).
    const userInfo = await openidClient.fetchUserInfo(singpassConfig, tokens.access_token, idTokenClaims.sub);
    console.log('This is the user info returned:');
    console.log(userInfo);

    ctx.session.user = { ...idTokenClaims, ...userInfo };
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
