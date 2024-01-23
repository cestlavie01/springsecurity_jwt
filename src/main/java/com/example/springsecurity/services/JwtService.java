package com.example.springsecurity.services;

import com.example.springsecurity.entities.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.HashMap;
import java.util.Map;

public interface JwtService {
    String generateToken(UserDetails userDetails);

    public String generateRefreshToken(Map<String, Object> extraClaim, UserDetails userDetails);

    String extractUserName(String token);

    boolean isTokenValid(String token, UserDetails userDetails);
}
