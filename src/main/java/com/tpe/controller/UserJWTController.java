package com.tpe.controller;
//Bu class sadece jwt ile ilgili endpointleri içereceği için özel bir kntroller
//sadece register ve login endpointleri olacak


import com.tpe.dto.LoginRequest;
import com.tpe.dto.RegisterRequest;
import com.tpe.security.JwtUtils;
import com.tpe.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

@RestController
@RequestMapping // http:/localhost:8080/

public class UserJWTController {

    @Autowired
    private UserService userService;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtils jwtUtils;

    // Not: REGISTER ****************************
    @PostMapping("/register")  // http://localhost:8080/register
    public ResponseEntity<String> registerUser(@Valid @RequestBody RegisterRequest request) {
        userService.registerUser(request);
        String responseMessage = "User is registered Successfully";

        return new ResponseEntity<>(responseMessage, HttpStatus.CREATED);
    }


    //Not: LOGIN ********************************
    @PostMapping("/login")  // http://localhost:8080/login
    public ResponseEntity<String> login(@Valid @RequestBody LoginRequest request){
        //!!! username ve password bilgisini AuthManager ile kontrol ediyoruz
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUserName(), request.getPassword()));

        //!!! JWT token uretilecek
        String token = jwtUtils.generateToken(authentication);
        return new ResponseEntity<>(token,HttpStatus.CREATED);
    }
}
