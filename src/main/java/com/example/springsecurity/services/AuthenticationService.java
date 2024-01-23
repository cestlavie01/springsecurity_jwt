package com.example.springsecurity.services;

import com.example.springsecurity.dto.JwtAuthenticationResponse;
import com.example.springsecurity.dto.RefreshTokenRequest;
import com.example.springsecurity.dto.SignUpRequest;
import com.example.springsecurity.dto.SigninRequest;
import com.example.springsecurity.entities.User;

public interface AuthenticationService {

    User signup(SignUpRequest signUpRequest);

    JwtAuthenticationResponse signin(SigninRequest signinRequest);

    JwtAuthenticationResponse refreshToken(RefreshTokenRequest refreshTokenRequest);
}
