package com.example.security.demo.filter;

import com.example.security.demo.service.authentication.JwtService;
import com.example.security.demo.service.userdetails.dto.MyUserDetails;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * @author Manuel Gozzi
 */
@Slf4j
@Component
public class JwtTokenFilter extends OncePerRequestFilter {

    private final UserDetailsService userDetailsService;

    private final JwtService jwtService;

    @Autowired
    public JwtTokenFilter(UserDetailsService userDetailsService, JwtService jwtService) {
        this.userDetailsService = userDetailsService;
        this.jwtService = jwtService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // Get authorization header and validate
        final String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header == null || !header.startsWith("Bearer ")) {

            filterChain.doFilter(request, response);
            return;
        }

        // Get jwt token and validate
        final String token = header.split(" ")[1].trim();
        if (this.jwtService.isExpired(token)) {

            log.debug("Token is expired");
            filterChain.doFilter(request, response);
            return;
        }

        // Get user identity and set it on the spring security context
        MyUserDetails userDetails = (MyUserDetails) this.userDetailsService.loadUserByUsername(
                this.jwtService.usernameOf(token)
        );
        if (userDetails == null) {

            log.debug("No username found on token");
            filterChain.doFilter(request, response);
            return;
        }

        if (!this.jwtService.validate(token, userDetails)) {

            log.debug("Token is not valid");
            filterChain.doFilter(request, response);
            return;
        }

        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                userDetails,
                null,
                userDetails.getAuthorities()
        );

        authentication.setDetails(
                new WebAuthenticationDetailsSource().buildDetails(request)
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);
        filterChain.doFilter(request, response);
    }
}
