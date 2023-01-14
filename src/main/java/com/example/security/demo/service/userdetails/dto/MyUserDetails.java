package com.example.security.demo.service.userdetails.dto;

import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

/**
 * @author Manuel Gozzi
 */
@Getter
@Setter
public class MyUserDetails implements UserDetails {

    private List<String> authorities;

    private String encodedPassword;

    private String username;

    private Date passwordExpirationDate;

    private Date lastPasswordChange;

    private boolean locked;

    private boolean enabled;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {

        // Authorities list is always immutable
        return this.authorities != null && !this.authorities.isEmpty() ?
                Collections.unmodifiableList(
                        this.authorities.stream()
                                .map(SimpleGrantedAuthority::new)
                                .collect(Collectors.toList())
                )
                : Collections.emptyList();
    }

    @Override
    public String getPassword() {

        return this.encodedPassword;
    }

    @Override
    public String getUsername() {

        return this.username;
    }

    @Override
    public boolean isAccountNonExpired() {

        // It assumes that accounts never expire
        return false;
    }

    @Override
    public boolean isAccountNonLocked() {

        return this.locked;
    }

    @Override
    public boolean isCredentialsNonExpired() {

        return this.passwordExpirationDate == null || this.passwordExpirationDate.after(new Date());
    }

    @Override
    public boolean isEnabled() {

        return this.enabled;
    }
}
