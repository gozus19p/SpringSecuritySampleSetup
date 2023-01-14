package com.example.security.demo.service.userdetails;

import com.example.security.demo.service.userdetails.dto.MyUserDetails;
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

    private final Map<String, MyUserDetails> users = new HashMap<>();

    private final PasswordEncoder passwordEncoder;

    public MyUserDetailsService(PasswordEncoder passwordEncoder) {

        this.passwordEncoder = passwordEncoder;

        MyUserDetails admin = new MyUserDetails();
        admin.setUsername("admin");
        admin.setEncodedPassword(
                this.passwordEncoder.encode("test")
        );
        admin.setAuthorities(
                Collections.singletonList("ROLE_ADMIN")
        );

        this.users.put("admin", admin);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        return this.users.get(username);
    }

    public PasswordEncoder getPasswordEncoder() {
        return this.passwordEncoder;
    }
}
