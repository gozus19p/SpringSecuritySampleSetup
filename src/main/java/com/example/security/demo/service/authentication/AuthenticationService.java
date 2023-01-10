package com.example.security.demo.service.authentication;

import com.example.security.demo.service.authentication.exception.HttpStatusException;
import com.example.security.demo.service.userdetails.MyUserDetailsService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;

/**
 * @author Manuel Gozzi
 */
@Slf4j
@Service
public class AuthenticationService {

    private final MyUserDetailsService myUserDetailsService;

    @Value("${app.session.max-inactive-interval-duration}")
    private Duration httpSessionMaxInactiveIntervalDuration;

    @Autowired
    public AuthenticationService(MyUserDetailsService myUserDetailsService) {
        this.myUserDetailsService = myUserDetailsService;
    }

    public List<String> login(
            HttpServletRequest request
    ) {

        BasicAuthCredentials basicAuthCredentials = this.parseBasicCredentials(request);

        UserDetails user = this.myUserDetailsService.loadUserByUsername(basicAuthCredentials.getUsername());
        if (this.myUserDetailsService.getPasswordEncoder().matches(basicAuthCredentials.getPassword(), user.getPassword())) {

            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    user,
                    user.getPassword(),
                    user.getAuthorities()
            );
            SecurityContext context = SecurityContextHolder.getContext();
            context.setAuthentication(authentication);

            /*
             * Controllo l'esistenza di sessioni precedenti. Se ne trovo, restituisco eccezione (poiché posso procedere
             * con il login solamente se non esistono altre sessioni precedenti).
             */
            HttpSession preExistingSession = request.getSession(false);
            if (preExistingSession != null) {

                // Restituisco un 409
                throw new HttpStatusException(
                        HttpStatus.CONFLICT,
                        String.format(
                                "User with username [%s] is already logged in",
                                basicAuthCredentials.getUsername()
                        )
                );
            }

            HttpSession session = request.getSession(true);
            session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, context);
            session.setMaxInactiveInterval(this.httpSessionMaxInactiveIntervalDuration.toSecondsPart());

            // Restituisco l'elenco delle authorities (dei ruoli) possedute dall'utente
            return user.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList());
        } else {

            throw new HttpStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials provided");
        }
    }

    public void logout(
            HttpServletRequest request
    ) {

        HttpSession session = request.getSession(false);
        if (session == null)
            throw new HttpStatusException(HttpStatus.NOT_ACCEPTABLE, "No session found, the user can't log out");

        session.invalidate();
    }

    private BasicAuthCredentials parseBasicCredentials(HttpServletRequest request) {

        String authorization = request.getHeader("Authorization");
        if (authorization == null)
            throw new HttpStatusException(HttpStatus.NOT_ACCEPTABLE, "No authorization header has been provided");

        if (!authorization.startsWith("Basic "))
            throw new HttpStatusException(HttpStatus.NOT_ACCEPTABLE, "The provided authorization is not in form of Basic");

        try {

            String[] usernameAndPassword = new String(
                    Base64.getDecoder()
                            .decode(authorization.replace("Basic ", "")),
                    StandardCharsets.UTF_8
            ).split(":");

            return new BasicAuthCredentials(usernameAndPassword[0], usernameAndPassword[1]);
        } catch (Exception e) {

            log.error(e.getMessage());
            throw new HttpStatusException(HttpStatus.NOT_ACCEPTABLE, "Malformed Basic Authorization has been provided");
        }
    }

    @Getter
    @Setter
    @AllArgsConstructor
    private static final class BasicAuthCredentials {

        private String username;

        private String password;
    }
}
