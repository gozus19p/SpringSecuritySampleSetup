package com.example.security.demo.service.authentication;

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

    public String usernameOf(String token) {

        return this.parseClaimsFromToken(token)
                .getSubject();
    }

    public boolean isExpired(String token) {

        Date expiration = this.parseClaimsFromToken(token)
                .getExpiration();

        return new Date().after(expiration);
    }

    public String create(UserDetails userDetails) {

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

    private Claims parseClaimsFromToken(String token) {

        return Jwts.parser()
                .setSigningKey(this.getKey())
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getKey() {

        return new SecretKeySpec(Base64.getDecoder().decode(this.secret), SignatureAlgorithm.HS512.getJcaName());
    }
}
