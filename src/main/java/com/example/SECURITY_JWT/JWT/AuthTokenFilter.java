package com.example.SECURITY_JWT.JWT;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.logging.Logger;

@Component
public class AuthTokenFilter extends OncePerRequestFilter {

    // this is a class to implement a custom filter for the security
    @Autowired
    private JWT_utils jwtUtils ;

    @Autowired
    private UserDetailsService userDetailsService;

//    private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            String jwt = parseJwt(request); // we are extracting the token from the request



            // after we get the token we need to validate it
            if(jwt != null && jwtUtils.validateJwtToken(jwt))
            {
                String username = jwtUtils.getUserNameFromToken(jwt);

                UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                //creating a authentication token
                UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities() // this indeicates what roles the user have
                );

                // this is to enhance the details like add the session id and other things to the auth token
                auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // now we need to add this to the security context so that we can refer it to process any request from this user
                SecurityContextHolder.getContext().setAuthentication(auth);
            }

        }catch (Exception e ){
            System.out.println("the exception found is" + e);
        }

        // continuing the filter chain
        filterChain.doFilter(request , response);
    }

    private String parseJwt(HttpServletRequest request) {
        String jwt = jwtUtils.getJwtTokenFromHeader(request);
        return jwt;
    }

}
