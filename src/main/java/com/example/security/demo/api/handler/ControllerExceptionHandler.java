package com.example.security.demo.api.handler;

import com.example.security.demo.service.authentication.exception.HttpStatusException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * @author Manuel Gozzi
 */
@Slf4j
@RestControllerAdvice
public class ControllerExceptionHandler {

    @ExceptionHandler(HttpStatusException.class)
    public ResponseEntity<Void> httpStatusException(HttpStatusException e) {

        log.error("An error occurred: {}", e.getMessage(), e);
        return ResponseEntity.status(e.getHttpStatus())
                .build();
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Void> exception(Exception e) {

        log.error("An error occurred: [{}]", e.getMessage(), e);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .build();
    }
}
