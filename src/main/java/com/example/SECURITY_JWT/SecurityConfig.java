package com.example.SECURITY_JWT;

import com.example.SECURITY_JWT.JWT.AuthEntryPointJwt;
import com.example.SECURITY_JWT.JWT.AuthTokenFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.sql.DataSource;
import java.util.Collections;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Autowired
    DataSource dataSource; // this will be provided to the jdbc manager

    @Autowired
    private AuthEntryPointJwt unauthorizedHandeler;

    @Bean
    public AuthTokenFilter authJwtTokenFilter(){
        return new AuthTokenFilter();
    }

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {

        http.authorizeHttpRequests( requests -> {
            ( (AuthorizeHttpRequestsConfigurer.AuthorizedUrl)requests.requestMatchers("/h2-console/**").permitAll().requestMatchers("/signin").permitAll()
                    .anyRequest() ).authenticated();
        });

        http.sessionManagement(
                session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        ); // this line of code prevents the cookies form being created

        http.httpBasic(Customizer.withDefaults());
        http.headers( headers -> headers.frameOptions(
                HeadersConfigurer.FrameOptionsConfig::sameOrigin
        ));
        http.csrf(csrf -> csrf.disable());

        // we are adding an exception handeling mechanism
        http.exceptionHandling(httpSecurityExceptionHandlingConfigurer -> httpSecurityExceptionHandlingConfigurer.authenticationEntryPoint(unauthorizedHandeler));

        //        http.headers( headers -> headers.frameOptions(
        //                frameOptionsConfig -> frameOptionsConfig.sameOrigin()
        //        ));

        //adding the custom filter
        http.addFilterBefore(new AuthTokenFilter() , UsernamePasswordAuthenticationFilter.class);

        return (SecurityFilterChain)http.build();
    }

    // writing code for in memory configuration

    // saperating the process of creating the UserDetailsService bean and adding the data into the table
    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource)
    {
        return new JdbcUserDetailsManager(dataSource);
    }

    @Bean
    public CommandLineRunner initData(UserDetailsService userDetailsService)
    {
        return args -> {

            JdbcUserDetailsManager manager = (JdbcUserDetailsManager) userDetailsService;

            UserDetails user1 =  User.withUsername("user1")
                .password(passwordEncoder().encode("u1"))
                .roles("USER")
                .build();

            UserDetails user2 =  User.withUsername("user2")
                .password(passwordEncoder().encode("u2")) // {noop} makes the spring boot to store teh password in plain text
                .roles("ADMIN")
                .build();

            JdbcUserDetailsManager userDetailsManager = new JdbcUserDetailsManager(dataSource);
            userDetailsManager.createUser(user1);
            userDetailsManager.createUser(user2);

        };
    }

    // using a password encoder for encoding the password
    @Bean
    public PasswordEncoder passwordEncoder()
    {
        return new BCryptPasswordEncoder(); // this uses the BYCRYPT algorithm
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration builder) throws Exception {
         return builder.getAuthenticationManager();
    }
}
