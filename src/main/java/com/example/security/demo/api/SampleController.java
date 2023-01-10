package com.example.security.demo.api;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author Manuel Gozzi
 */
@RestController
@RequestMapping("/api/v1/sample")
public class SampleController {

    @GetMapping("/hello")
    public String helloWorld() {

        return "Hello world!";
    }

    @GetMapping("/protection")
    public String protection() {

        return "Only authenticated users!";
    }
}
