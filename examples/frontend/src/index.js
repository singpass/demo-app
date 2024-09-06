const BACKEND_URL = 'http://localhost:5081';

const backendClient = (function makeBackendClient() {
  const CODE_CHALLENGE = 'code_challenge';
  const parseJson = (res) => res.json();

  async function getAuthorizationUrl() {
    const { url } = await fetch(`${BACKEND_URL}/auth/authorization`).then(
      parseJson
    );
    // temporarily store code_challenge
    sessionStorage.setItem(
      CODE_CHALLENGE,
      new URL(url).searchParams.get(CODE_CHALLENGE)
    );
    return url;
  }

  function getClaims(params) {
    const code_challenge = sessionStorage.getItem(CODE_CHALLENGE);
    sessionStorage.removeItem(CODE_CHALLENGE);
    return fetch(`${BACKEND_URL}/auth/claims`, {
      method: 'POST',
      body: JSON.stringify({
        code_challenge,
        ...Object.fromEntries(params.entries()),
      }),
      headers: { 'content-type': 'application/json' },
    }).then(parseJson);
  }
  return { getAuthorizationUrl, getClaims };
})();

document.getElementById('loginBtn').onclick =
  async function handleLoginBtnClick() {
    window.location.href = await backendClient.getAuthorizationUrl();
  };
document.getElementById('logoutBtn').onclick = function handleLogout() {
  window.location.href = '/';
};

(async function handleSingpassCallback() {
  const url = new URL(location.href);
  if ('/callback' !== url.pathname) {
    return;
  }

  const claims = await backendClient.getClaims(url.searchParams);
  document.getElementById('claims').innerText = JSON.stringify(claims);
  document.getElementById('loginBtn').remove();
  document.getElementById('logoutBtn').hidden = null;
})();
