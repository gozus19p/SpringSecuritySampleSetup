package com.example.security.demo.service.authentication;

import com.example.security.demo.service.userdetails.dto.MyUserDetails;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * @author Manuel Gozzi
 */
@Service
public class JwtService {

    @Value("${app.jwt.secret}")
    private String secret;

    /**
     * It reads the username of the given JWT token.
     *
     * @param token is the JWT token to parse
     * @return the subject's username in form of {@link String}
     */
    public String usernameOf(String token) {

        return this.parseClaimsFromToken(token)
                .getSubject();
    }

    /**
     * It checks if the given JWT token is expired or not.
     *
     * @param token is the JWT token to check
     * @return <code>true</code> if the JWT is expired, <code>false</code> otherwise
     */
    public boolean isExpired(String token) {

        Date expiration = this.parseClaimsFromToken(token)
                .getExpiration();

        return new Date().after(expiration);
    }

    public boolean validate(String token, MyUserDetails myUserDetails) {

        // If the token is expired, it is not valid
        if (this.isExpired(token)) return false;

        if (myUserDetails.getLastPasswordChange() != null) {

            // Token is valid if it has been issued after the last password change, if any
            return this.parseClaimsFromToken(token)
                    .getIssuedAt()
                    .after(myUserDetails.getLastPasswordChange());
        }

        // Otherwise, it is valid
        return true;
    }

    /**
     * It creates a new JWT starting from a user in form of {@link UserDetails}.
     *
     * @param userDetails is the user to start from
     * @return the created JWT
     */
    public String create(MyUserDetails userDetails) {

        Date iat = new Date();
        return Jwts.builder()
                .setSubject(userDetails.getUsername())

                // TODO add other claims
                .claim(
                        "roles",
                        userDetails.getAuthorities().stream()
                                .map(GrantedAuthority::getAuthority)
                                .collect(Collectors.toList())
                )
                .setId(UUID.randomUUID().toString())
                .setIssuedAt(iat)
                .setExpiration(new Date(iat.getTime() + (1_000 * 60 * 5)))
                .signWith(SignatureAlgorithm.HS512, this.getKey())
                .compact();
    }

    /**
     * It parses the given token and returns the related {@link Claims}.
     *
     * @param token is the JWT token
     * @return the {@link Claims}
     */
    private Claims parseClaimsFromToken(String token) {

        return Jwts.parser()
                .setSigningKey(this.getKey())
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * It returns the {@link Key} used to sign JWT. The algorithm used is {@link SignatureAlgorithm#HS512}.
     *
     * @return the {@link Key} to use to sign JWT
     */
    private Key getKey() {

        return new SecretKeySpec(
                Base64.getDecoder()
                        .decode(this.secret),
                SignatureAlgorithm.HS512.getJcaName()
        );
    }
}
