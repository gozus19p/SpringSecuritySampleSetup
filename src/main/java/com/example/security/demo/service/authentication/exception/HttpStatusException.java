package com.example.security.demo.service.authentication.exception;

import org.springframework.http.HttpStatus;

/**
 * @author Manuel Gozzi
 */
public class HttpStatusException extends RuntimeException {

    private final HttpStatus httpStatus;

    private final String message;

    public HttpStatusException(HttpStatus status) {
        this(status, status.getReasonPhrase());
    }

    public HttpStatusException(HttpStatus status, String message) {
        this.httpStatus = status;
        this.message = message;
    }

    @Override
    public String getMessage() {

        return String.format("HTTP [%s]: [%s]", this.httpStatus.value(), this.message);
    }

    public HttpStatus getHttpStatus() {

        return this.httpStatus;
    }
}
