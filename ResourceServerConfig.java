package com.usermngmnt.config;

import com.usermngmnt.JwtOpaqueTokenIntrospector;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Value("${spring.security.oauth2.resourceserver.opaque.introspection-uri}")
    String introspectionUri;

    @Value("${spring.security.oauth2.resourceserver.opaque.introspection-client-id}")
    String clientId;

    @Value("${spring.security.oauth2.resourceserver.opaque.introspection-client-secret}")
    String clientSecret;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests((authorize) -> authorize
                        .requestMatchers(HttpMethod.GET, "/welcome").hasAuthority("SCOPE_openid")
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer((oauth2) -> oauth2
                        .opaqueToken((opaque) -> opaque
                                .introspectionUri(this.introspectionUri)
                                .introspectionClientCredentials(this.clientId, this.clientSecret)
                                .authenticationConverter(introspectionAuthenticationConverter())
                        )
                );
        return http.build();
    }

    @Bean
    public OpaqueTokenAuthenticationConverter introspectionAuthenticationConverter() {
        return (String introspectedToken, OAuth2AuthenticatedPrincipal authenticatedPrincipal) ->
                new BearerTokenAuthentication(
                        authenticatedPrincipal,
                        new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, introspectedToken, authenticatedPrincipal.getAttribute(IdTokenClaimNames.IAT), authenticatedPrincipal.getAttribute(IdTokenClaimNames.EXP)),
                        ((List<String>)authenticatedPrincipal.getAttribute("user-authorities")).stream().map(SimpleGrantedAuthority::new).toList());
    }
}