package com.taitech.spring_security.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.Value;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {
    private static String secretKey;
    private static Long expiry;

    @Autowired
    public JwtService(JwtProperties jwtProperties){

        secretKey = jwtProperties.getSecret();
        expiry = jwtProperties.getExpiration();
    }

    //Method to generate JWT without extract claims
    public String generateToken( UserDetails userDetails){
        return generateToken(new HashMap<>(), userDetails);

    }
    //Method to generate JWT with extract claims
    public String generateToken(Map<String, Object> extractClaims, UserDetails userDetails){
        return Jwts
                .builder()
                .setClaims(extractClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                //.setExpiration(new Date(((System.currentTimeMillis() / 1000) / 3600) * 24 ))
                .setExpiration(new Date(System.currentTimeMillis() + expiry))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    //method to validate a token
    public boolean isTokenValid(String token, UserDetails userDetails){
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));

    }

    //Method to check if token is expired
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    //Method to extract token expiration
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }


    //Extract Claim subject (email/username)
    public String extractUsername(String token){

        //return "Username/email";
        return extractClaim(token, Claims::getSubject);

    }

    //Method to extract 1 claim
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver){
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }


    //Method to extract all claims
    public Claims extractAllClaims(String token){
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();

    }

    //Decode Key using Base64 and return it
    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
