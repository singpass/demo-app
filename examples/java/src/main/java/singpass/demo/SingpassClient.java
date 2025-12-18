package singpass.demo;

import java.net.URI;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.JWEDecryptionKeySelector;
import com.nimbusds.jose.proc.JWSAlgorithmFamilyJWSKeySelector;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.PushedAuthorizationRequest;
import com.nimbusds.oauth2.sdk.PushedAuthorizationResponse;
import com.nimbusds.oauth2.sdk.PushedAuthorizationSuccessResponse;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.JWTAuthenticationClaimsSet;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.dpop.DPoPUtils;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.DPoPAccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;

/**
 * SingpassClient handles all OIDC interactions with the Singpass authorization server.
 * It is implemented using the Nimbus OAuth2.0 SDK with OpenID Connect extensions,
 * which is an off-the-shelf library for implementing OIDC clients in Java.
*/
public class SingpassClient {
    private final ConfigLoader cfg;
    private OIDCProviderMetadata providerMeta;
    private long lastRefresh;
    private JWKSource<SecurityContext> encryptionKeyJwkSource;
    private JWSKeySelector<SecurityContext> jwsVerificationKeySelector;

    public SingpassClient(ConfigLoader config) throws Exception {
        this.cfg = config;
        refreshMetadata();

        // initialize encryption key JWK source to be used for decrypting ID tokens and userinfo responses
        JWKSet encryptionKeyJwkSet = new JWKSet(cfg.privateEncryptionKey);
        this.encryptionKeyJwkSource = (jwkSelector, context) -> jwkSelector
                .select(encryptionKeyJwkSet);
    }

    /**
    * Fetches the OpenID Provider configuration from the well-known endpoint.
    * This discovery document tells us where all the OAuth2/OIDC endpoints are located.
    * To keep your Singpass OIDC client up-to-date with any changes to Singpass' OIDC config, 
    * we recommend reinitializing it periodically (an hour or more apart). 
    * This pulls the latest OIDC config and updates the client accordingly.
    */
    public void refreshMetadata() throws Exception {
        this.providerMeta = OIDCProviderMetadata.resolve(new Issuer(cfg.issuerUrl));
        this.lastRefresh = System.currentTimeMillis();
        // initialize JWS verification key selector to be used for verifying ID tokens and userinfo responses
        this.jwsVerificationKeySelector = JWSAlgorithmFamilyJWSKeySelector
                .fromJWKSource(JWKSourceBuilder.create(providerMeta.getJWKSetURI().toURL()).build());
    }

    public void refreshIfNeeded() throws Exception {
        long oneHour = 60 * 60 * 1000;
        if (System.currentTimeMillis() - lastRefresh > oneHour) {
            refreshMetadata();
        }
    }

    public ECKey generateDPoPKey() throws Exception {
        return new ECKeyGenerator(Curve.P_256)
                .algorithm(JWSAlgorithm.ES256)
                .keyID(UUID.randomUUID().toString())
                .generate();
    }

    private SignedJWT createDPoPProof(String httpMethod, URI uri, ECKey dpopKey, AccessToken accessToken)
            throws Exception {
        JWSAlgorithm alg = JWSAlgorithm.parse(dpopKey.getAlgorithm().getName());
        JWSHeader jwsHeader = new JWSHeader.Builder(alg)
                .type(new JOSEObjectType("dpop+jwt"))
                .jwk(dpopKey.toPublicJWK())
                .build();
        JWSSigner signer = new DefaultJWSSignerFactory().createJWSSigner(dpopKey, alg);

        // note: DPoPUtils provided by nimbus does not set expiration time
        // so we add expiration time manually
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder(
                DPoPUtils.createJWTClaimsSet(new JWTID(), httpMethod, uri, new Date(), accessToken, null))
                .expirationTime(new Date(new Date().getTime() + 60 * 1000))
                .build();

        SignedJWT signedJWT = new SignedJWT(jwsHeader, jwtClaimsSet);
        signedJWT.sign(signer);
        return signedJWT;
    }

    private ClientAuthentication createClientAuth(URI endpoint) throws Exception {
        JWTAuthenticationClaimsSet claimsSet = new JWTAuthenticationClaimsSet(
                cfg.clientId,
                new Audience(endpoint.toString()).toSingleAudienceList(),
                new Date(new Date().getTime() + 60 * 1000),
                null,
                new Date(),
                new JWTID());

        return new PrivateKeyJWT(claimsSet, JWSAlgorithm.parse(cfg.privateSigningKey.getAlgorithm().getName()),
                cfg.privateSigningKey.toPrivateKey(),
                cfg.privateSigningKey.getKeyID(), null);
    }

    public URI buildAuthUrl(CodeVerifier verifier, Nonce nonce, State state, ECKey dpopKey) throws Exception {
        AuthenticationRequest authReq = new AuthenticationRequest.Builder(
                new ResponseType("code"),
                new Scope(cfg.scopes.split(" ")),
                cfg.clientId,
                cfg.redirectUri)
                .nonce(nonce)
                .codeChallenge(verifier, CodeChallengeMethod.S256)
                .state(state)
                .endpointURI(providerMeta.getAuthorizationEndpointURI())
                .build();

        URI parEndpoint = providerMeta.getPushedAuthorizationRequestEndpointURI();
        ClientAuthentication clientAuth = createClientAuth(parEndpoint);

        PushedAuthorizationRequest par = new PushedAuthorizationRequest(
                parEndpoint,
                clientAuth,
                authReq);

        HTTPRequest httpReq = par.toHTTPRequest();
        httpReq.setDPoP(createDPoPProof("POST", parEndpoint, dpopKey, null));

        HTTPResponse parResp = httpReq.send();
        PushedAuthorizationResponse parsedResp = PushedAuthorizationResponse.parse(parResp);

        if (!parsedResp.indicatesSuccess()) {
            throw new Exception("PAR failed: " + parResp.getBody());
        }

        PushedAuthorizationSuccessResponse success = parsedResp.toSuccessResponse();

        return new AuthorizationRequest.Builder(
                new ResponseType("code"),
                cfg.clientId)
                .requestURI(success.getRequestURI())
                .endpointURI(providerMeta.getAuthorizationEndpointURI())
                .build()
                .toURI();
    }

    public AuthorizationCode getAuthCodeFromCallback(URI callbackUri, State expectedState) throws Exception {
        AuthenticationResponse response = AuthenticationResponseParser.parse(callbackUri);
        if (response instanceof AuthenticationErrorResponse) {
            throw new Exception(String.format("Authentication error: %s - %s",
                    ((AuthenticationErrorResponse) response).getErrorObject().getCode(),
                    ((AuthenticationErrorResponse) response).getErrorObject().getDescription()));
        }
        if (!response.getState().equals(expectedState)) {
            throw new Exception("Invalid state in callback");
        }
        return response.toSuccessResponse().getAuthorizationCode();
    }

    private OIDCTokenResponse makeTokenRequest(AuthorizationCode code, CodeVerifier verifier, ECKey dpopKey)
            throws Exception {
        URI tokenEndpoint = providerMeta.getTokenEndpointURI();
        ClientAuthentication clientAuth = createClientAuth(tokenEndpoint);

        TokenRequest tokenReq = new TokenRequest(
                tokenEndpoint,
                clientAuth,
                new AuthorizationCodeGrant(code,
                        cfg.redirectUri, verifier));

        HTTPRequest tokenHttpReq = tokenReq.toHTTPRequest();
        tokenHttpReq.setDPoP(createDPoPProof("POST", tokenEndpoint, dpopKey, null));

        HTTPResponse tokenResp = tokenHttpReq.send();
        TokenResponse parsedTokenResp = OIDCTokenResponseParser.parse(tokenResp);

        if (!parsedTokenResp.indicatesSuccess()) {
            throw new Exception("Token exchange failed: " + tokenResp.getBody());
        }
        return (OIDCTokenResponse) parsedTokenResp.toSuccessResponse();
    }

    private IDTokenClaimsSet decryptAndParseIdToken(OIDCTokenResponse tokenResp, Nonce nonce) throws Exception {
        JWEObject jweObject = JWEObject.parse(tokenResp.getOIDCTokens().getIDToken().getParsedString());
        JWEDecryptionKeySelector<SecurityContext> jweKeySelector = new JWEDecryptionKeySelector<>(
                jweObject.getHeader().getAlgorithm(),
                jweObject.getHeader().getEncryptionMethod(),
                encryptionKeyJwkSource);
        IDTokenValidator idTokenValidator = new IDTokenValidator(
                providerMeta.getIssuer(),
                cfg.clientId,
                jwsVerificationKeySelector,
                jweKeySelector);

        return idTokenValidator.validate(
                tokenResp.getOIDCTokens().getIDToken(),
                nonce);
    }

    private JWT makeUserInfoRequest(ECKey dpopKey, DPoPAccessToken accessToken) throws Exception {
        URI userInfoEndpoint = providerMeta.getUserInfoEndpointURI();
        UserInfoRequest userInfoReq = new UserInfoRequest(
                userInfoEndpoint,
                accessToken);

        HTTPRequest userInfoHttpReq = userInfoReq.toHTTPRequest();
        userInfoHttpReq.setDPoP(createDPoPProof("GET", userInfoEndpoint, dpopKey, accessToken));

        HTTPResponse userInfoResp = userInfoHttpReq.send();
        UserInfoResponse parsedUserInfo = UserInfoResponse.parse(userInfoResp);

        if (!parsedUserInfo.indicatesSuccess()) {
            throw new Exception("UserInfo failed: " + userInfoResp.getBody());
        }

        return parsedUserInfo.toSuccessResponse().getUserInfoJWT();
    }

    private Map<String, Object> decryptAndParseUserInfo(JWT userInfoJWT) throws Exception {
        JWEObject jweObject = JWEObject.parse(userInfoJWT.getParsedString());

        JWEDecryptionKeySelector<SecurityContext> jweKeySelector = new JWEDecryptionKeySelector<>(
                jweObject.getHeader().getAlgorithm(),
                jweObject.getHeader().getEncryptionMethod(),
                encryptionKeyJwkSource);

        ConfigurableJWTProcessor<SecurityContext> userInfoJwtProcessor = new DefaultJWTProcessor<>();
        userInfoJwtProcessor.setJWSKeySelector(jwsVerificationKeySelector);
        userInfoJwtProcessor.setJWEKeySelector(jweKeySelector);

        JWTClaimsSet userInfoClaimsSet = userInfoJwtProcessor.process(userInfoJWT, null);
        return userInfoClaimsSet.getClaims();
    }

    public Map<String, Object> exchangeCode(AuthorizationCode code, CodeVerifier verifier, Nonce nonce,
            State state, URI callbackUri, ECKey dpopKey) throws Exception {
        OIDCTokenResponse tokenResp = makeTokenRequest(code, verifier, dpopKey);
        IDTokenClaimsSet idTokenClaims = decryptAndParseIdToken(tokenResp, nonce);
        System.out.println("These are the claims in the ID token:");
        System.out.println(idTokenClaims.toJSONObject());

        DPoPAccessToken accessToken = tokenResp.getTokens().getDPoPAccessToken();
        JWT userInfoJWT = makeUserInfoRequest(dpopKey, accessToken);
        Map<String, Object> userInfoClaims = decryptAndParseUserInfo(userInfoJWT);

        System.out.println("This is the user info returned:");
        System.out.println(userInfoClaims);

        Map<String, Object> combinedClaims = new HashMap<String, Object>();
        combinedClaims.putAll(idTokenClaims.toJSONObject());
        combinedClaims.putAll(userInfoClaims);
        return combinedClaims;
    }
}