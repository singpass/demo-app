/*** 1. Initialize a backend client ***/
const backendClient = (function makeBackendClient() {
  const BACKEND_URL = 'http://localhost:5081';
  const CODE_CHALLENGE = 'code_challenge';
  const parseJson = (res) => res.json();

  /** Retrieve Singpass authorization URL
   * @returns {Promise<string>}
   */
  async function getAuthorizationUrl() {
    const { url } = await fetch(`${BACKEND_URL}/auth/authorization`).then(
      parseJson
    );
    /** This code_challenge is used in retrieving claims/access_token after user logged in with Singpass **/
    sessionStorage.setItem(
      CODE_CHALLENGE,
      new URL(url).searchParams.get(CODE_CHALLENGE)
    );
    return url;
  }

  /** Retrieve claims or access_token
   * @param {URLSearchParams} params (includes auth code and state)
   * @returns {Promise<*>}
   */
  function getClaims(params) {
    /** Extract and remove code_challenge stored **/
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

/*** 2. Retrieve authorization URL and redirect users to Singpass login page ***/
document.getElementById('loginBtn').onclick =
  async function handleLoginBtnClick() {
    window.location.href = await backendClient.getAuthorizationUrl();
  };

document.getElementById('logoutBtn').onclick = function handleLogout() {
  window.location.href = '/';
};

/*** 3. Handle Singpass login callback ***/
(async function handleSingpassCallback() {
  const url = new URL(location.href);
  if ('/callback' !== url.pathname) {
    return;
  }

  /** Pass auth code and state to the backend in exchange for an access_token or user profile **/
  const claims = await backendClient.getClaims(url.searchParams);
  document.getElementById('claims').innerText = JSON.stringify(claims);
  document.getElementById('loginBtn').remove();
  document.getElementById('logoutBtn').hidden = null;
})();
