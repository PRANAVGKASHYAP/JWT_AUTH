package com.example.SECURITY_JWT.JWT;


import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;
import java.util.logging.Logger;

@Component
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class JWT_utils {
    //this is a class that has necessary functions to work with JWT

    private static final Logger logger = Logger.getLogger(JWT_utils.class.getName());

    @Value("${spring.application.secret}")
    private String jwtSecret;

    @Value("${spring.application.time}")
    private int jwtExpTime;

    public String getJwtTokenFromHeader(HttpServletRequest request)
    {
        String bearerToken = request.getHeader("Authorization");

        if(bearerToken != null && bearerToken.startsWith("Bearer ")){
            return bearerToken.substring(7);
        }

        else{
            return null;
        }
    }

    public String generateTokenFromUserName(UserDetails userDetails)
    {
        String username = userDetails.getUsername();

        return Jwts.builder()
                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date( (new Date()).getTime() + jwtExpTime ))
                .signWith(key())
                .compact();
    }

    public Key key(){
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }

    public String getUserNameFromToken(String token)
    {
        return Jwts.parser()
                .verifyWith((SecretKey) key() )
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }

    public boolean validateJwtToken(String token)
    {
        try {
            System.out.println("validate");
            Jwts.parser()
                    .verifyWith((SecretKey) key() )
                    .build()
                    .parseSignedClaims(token);
            return true;
        }catch (MalformedJwtException e){
            logger.info("Invalid JWT token");
        }catch (ExpiredJwtException e){
            logger.info("Expired JWT token");
        }

        return false;
    }

}
