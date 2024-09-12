package sg.gov.singpass.developer;

import com.nimbusds.jose.jwk.JWK;
import lombok.SneakyThrows;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.endpoint.*;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenDecoderFactory;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

  @Bean
  public SecurityFilterChain securityFilterChain(
      HttpSecurity http, OAuth2AuthorizationRequestResolver resolver) throws Exception {
    http.authorizeHttpRequests(
            authorize ->
                authorize.requestMatchers("/api/user").authenticated().anyRequest().permitAll())
        .logout(logout -> logout.logoutSuccessUrl("/"))
        .exceptionHandling(
            exception ->
                exception.defaultAuthenticationEntryPointFor(
                    new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED),
                    new AntPathRequestMatcher("/api/**")))
        .oauth2Login(
            login ->
                login
                    .successHandler(
                        (request, response, authentication) -> response.sendRedirect("/"))
                    .authorizationEndpoint(
                        endpoint -> endpoint.authorizationRequestResolver(resolver))
                    .redirectionEndpoint(endpoint -> endpoint.baseUri("/callback")));
    return http.build();
  }

  @Bean
  public OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest>
      authorizationCodeGrantResponseClient() {
    DefaultAuthorizationCodeTokenResponseClient client =
        new DefaultAuthorizationCodeTokenResponseClient();
    client.setRequestEntityConverter(authCodeRequestConverter());
    return client;
  }

  // Enable PKCE
  @Bean
  public OAuth2AuthorizationRequestResolver authorizationRequestResolver(
      ClientRegistrationRepository clientRegistrationRepository) {
    DefaultOAuth2AuthorizationRequestResolver resolver =
        new DefaultOAuth2AuthorizationRequestResolver(
            clientRegistrationRepository, "/oauth2/authorization");

    resolver.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());
    return resolver;
  }

  // The default algorithm is RS256 but Singpass uses ES256 to sign id_token
  @Bean
  public JwtDecoderFactory<ClientRegistration> idTokenDecoderFactory() {
    OidcIdTokenDecoderFactory factory = new OidcIdTokenDecoderFactory();
    factory.setJwsAlgorithmResolver(client -> SignatureAlgorithm.ES256);
    return factory;
  }

  // Load your JWK private key to be used by Oauth2 Client
  private static OAuth2AuthorizationCodeGrantRequestEntityConverter authCodeRequestConverter() {
    OAuth2AuthorizationCodeGrantRequestEntityConverter requestConverter =
        new OAuth2AuthorizationCodeGrantRequestEntityConverter();
    requestConverter.addParametersConverter(
        new NimbusJwtClientAuthenticationParametersConverter<>(SecurityConfig::getPrivateSigKey));
    return requestConverter;
  }

  @SneakyThrows
  private static JWK getPrivateSigKey(ClientRegistration clientRegistration) {
    return JWK.parse(clientRegistration.getClientSecret());
  }
}
