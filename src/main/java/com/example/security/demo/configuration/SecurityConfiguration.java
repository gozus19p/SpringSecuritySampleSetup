package com.example.security.demo.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author Manuel Gozzi
 */
@Configuration
@RestController
public class SecurityConfiguration {


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
                                        .and()
                                        .csrf()
                                        .disable();
                            } catch (Exception e) {
                                throw new RuntimeException(e);
                            }
                        }
                );
        return http.build();
    }
}
