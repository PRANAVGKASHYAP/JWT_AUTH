package com.example.SECURITY_JWT;

import com.example.SECURITY_JWT.JWT.JWT_utils;
import com.example.SECURITY_JWT.JWT.LoginRequest;
import com.example.SECURITY_JWT.JWT.LoginResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class GreetingsController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JWT_utils jwtUtils;

    @GetMapping("/hello")
    public String sayHello()
    {
        return "Hello " ;
    }

    // creating role based end points
    @PreAuthorize("hasRole('USER')")
    @GetMapping("/user")
    public String userEndPoint()
    {
        return "user";
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin")
    public String adminEndPoint()
    {
        return "admin";
    }

    // writting the endpoints for the user to login

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest)
    {
        Authentication authentication;

        //try to authenticate the user and throw corresponding errors
        try {
            authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername() , loginRequest.getPassword()));
        }catch (AuthenticationException exception){
            //throwing the custom exception
            Map<String , Object> map = new HashMap<>();
            map.put("message" , "bad credentials");
            map.put("status" , "not authenticated");
            return new ResponseEntity<Object>(map , HttpStatus.NOT_FOUND);
        }

        // if there is no error that means we need to authorize this authenticated user

        // 1. set the context
        SecurityContextHolder.getContext().setAuthentication(authentication);

        //2. generate the token
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        //3. generate the token
        String token = jwtUtils.generateTokenFromUserName(userDetails);

        //4. check the roles given to this user
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        //5. generate the response
        LoginResponse loginResponse = new LoginResponse( token , userDetails.getUsername() , roles);

        return ResponseEntity.ok(loginResponse);
    }


}
