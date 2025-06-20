package com.alvirg.security.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {
    /*this controller will have two endpoints that will allow me
    to create or register a new account and authenticate an
    existing user
    endpoint1: register
    endpoint2: authenticate
    */

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(
            @RequestBody registerRequest
    ){
        //
    }

    @PostMapping("/autheticate")
    public ResponseEntity<AuthenticationResponse> register(
            @RequestBody AuthenticationRequest
            ){
        //
    }



}
