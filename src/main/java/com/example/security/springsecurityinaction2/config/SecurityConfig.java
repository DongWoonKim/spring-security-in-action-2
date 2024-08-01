package com.example.security.springsecurityinaction2.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        String expression = "hasAuthority(\"WRITE\") and !hasAuthority(\"DELETE\")";
        WebExpressionAuthorizationManager webExpressionAuthorizationManager = new WebExpressionAuthorizationManager(expression);

        http
                .httpBasic(Customizer.withDefaults())
                .authorizeHttpRequests(
                        authz -> authz.anyRequest()
//                                .hasAuthority("WRITE")
//                                .hasAnyAuthority("READ", "WRITE")
//                                .access(AuthorityAuthorizationManager.hasAuthority("WRITE"))
                                .access(webExpressionAuthorizationManager)
                );

        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        var manager = new InMemoryUserDetailsManager();

        var user1 = User.withUsername("john")
                .password("12345")
                .authorities("WRITE", "DELETE")
                .build();

        var user2 = User.withUsername("jane")
                .password("12345")
                .authorities("WRITE")
                .build();

        manager.createUser(user1);
        manager.createUser(user2);

        return manager;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

}
