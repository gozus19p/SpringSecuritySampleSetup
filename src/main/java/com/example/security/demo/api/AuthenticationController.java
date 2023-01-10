package com.example.security.demo.api;

import com.example.security.demo.service.authentication.AuthenticationService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * @author Manuel Gozzi
 */
@Slf4j
@RestController
@RequestMapping("/api/v1/auth")
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    @Autowired
    public AuthenticationController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @GetMapping("/login")
    public List<String> login(
            HttpServletRequest request
    ) {

        return this.authenticationService.login(request);
    }

    @GetMapping("/logout")
    public void logout(
            HttpServletRequest request
    ) {

        this.authenticationService.logout(request);
    }
}
