package com.example.SECURITY_JWT.JWT;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Component
public class AuthEntryPointJwt implements AuthenticationEntryPoint {

    private final HttpServletResponse httpServletResponse;

    public AuthEntryPointJwt(HttpServletResponse httpServletResponse) {
        this.httpServletResponse = httpServletResponse;
    }

    // this class is to handel un authorized requests or authentication related errors
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        System.out.println( "the exception that has occured during authentication is" + authException);

        // we can set the custom response to the auth errors/exception

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

        final Map<String  , Object>body = new HashMap<>();
        body.put("status" , HttpServletResponse.SC_UNAUTHORIZED);
        body.put("error" , "un authorized");
        body.put("message" , authException.getMessage());
        body.put("path" , request.getServletPath()); // this is the path that the user sent the request to

        // sending the above map as a response
        final ObjectMapper mapper = new ObjectMapper();
        mapper.writeValue(response.getOutputStream() , body);
    }
}
