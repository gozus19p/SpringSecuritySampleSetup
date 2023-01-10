package com.example.security.demo.service.userdetails;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Manuel Gozzi
 */
@Service
public class MyUserDetailsService implements UserDetailsService {

    private final Map<String, User> users = new HashMap<>();

    private final PasswordEncoder passwordEncoder;

    public MyUserDetailsService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;

        this.users.put(
                "admin",
                new User("admin", this.passwordEncoder.encode("test"), Collections.singletonList(new SimpleGrantedAuthority("ROLE_ADMIN")))
        );
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        return this.users.get(username);
    }

    public PasswordEncoder getPasswordEncoder() {
        return this.passwordEncoder;
    }
}
