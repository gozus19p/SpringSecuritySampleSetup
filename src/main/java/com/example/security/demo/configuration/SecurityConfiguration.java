package com.example.security.demo.configuration;

import com.example.security.demo.filter.JwtTokenFilter;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.bind.annotation.RestController;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * @author Manuel Gozzi
 */
@Configuration
@RestController
public class SecurityConfiguration {

    private final JwtTokenFilter jwtTokenFilter;

    @Value("${app.jwt.rsa-private-key}")
    private RSAPrivateKey rsaPrivateKey;

    @Value("${app.jwt.rsa-public-key}")
    private RSAPublicKey rsaPublicKey;

    @Autowired
    public SecurityConfiguration(JwtTokenFilter jwtTokenFilter) {
        this.jwtTokenFilter = jwtTokenFilter;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        // http builder configurations for authorize requests and form login (see below)
        http
                .authorizeHttpRequests((auth) ->
                        {
                            try {
                                auth
                                        .requestMatchers("/api/v1/auth/**").permitAll()
                                        .anyRequest().hasAuthority("ROLE_ADMIN")

                                        // Abilito il CORS
                                        .and()
                                        .cors()

                                        // Disabilito il CSRF
                                        .and()
                                        .csrf()
                                        .disable();

                                auth.and()

                                        // Gestione della sessione in modalità STATELESS
                                        .sessionManagement()
                                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                                        // Aggiungo il filtro JWT
                                        .and()
                                        .addFilterBefore(
                                                this.jwtTokenFilter,
                                                UsernamePasswordAuthenticationFilter.class
                                        );
                            } catch (Exception e) {
                                throw new RuntimeException(e);
                            }
                        }
                );
        return http.build();
    }

    // Used by JwtAuthenticationProvider to generate JWT tokens
    @Bean
    public JwtEncoder jwtEncoder() {

        RSAKey jwk = new RSAKey.Builder(this.rsaPublicKey)
                .privateKey(this.rsaPrivateKey)
                .build();
        return new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(jwk)));
    }

    // Used by JwtAuthenticationProvider to decode and validate JWT tokens
    @Bean
    public JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withPublicKey(this.rsaPublicKey).build();
    }
}
