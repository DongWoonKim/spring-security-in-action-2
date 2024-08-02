package com.example.security.springsecurityinaction2.config;

import com.example.security.springsecurityinaction2.filter.StaticKeyAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import static org.springframework.http.HttpMethod.*;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final StaticKeyAuthenticationFilter staticKeyAuthenticationFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        String expression = "hasAuthority(\"WRITE\") and !hasAuthority(\"DELETE\")";
        WebExpressionAuthorizationManager webExpressionAuthorizationManager = new WebExpressionAuthorizationManager(expression);

        http
//                .addFilterBefore(new RequestValidationFilter(), BasicAuthenticationFilter.class)
//                .addFilterAfter(new AuthenticationLoggingFilter(), BasicAuthenticationFilter.class)
                .addFilterAt( staticKeyAuthenticationFilter, BasicAuthenticationFilter.class )
                .csrf(c -> c.disable())
                .httpBasic(Customizer.withDefaults())
                .authorizeHttpRequests(
                        authz ->
                                authz
//                                        .anyRequest()
//                                .hasAuthority("WRITE")
//                                .hasAnyAuthority("READ", "WRITE")
//                                .access(AuthorityAuthorizationManager.hasAuthority("WRITE"))
//                                .access(webExpressionAuthorizationManager)
//                                .hasRole("ADMIN")
//                                    .requestMatchers("/hello").hasRole("ADMIN")
//                                    .requestMatchers("/ciao").hasRole("MANAGER")
//                                    .anyRequest()
//                                        .permitAll()
//                                        .authenticated()
                                        .requestMatchers(GET, "/hello").permitAll()
//                                        .requestMatchers(GET, "/a").authenticated()
//                                        .requestMatchers("/a/b/**").authenticated()
//                                        .requestMatchers(POST, "/a").permitAll()
//                                        .requestMatchers("/product/{code:^[0-9]*$}").permitAll()
                                        .requestMatchers("/video/{country:us|uk|ca}/{language:en|fr}").hasRole("MANAGER")
                                        .anyRequest().authenticated()
                );



        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        var manager = new InMemoryUserDetailsManager();

        var user1 = User.withUsername("john")
                .password("12345")
//                .authorities("ROLE_ADMIN")
                .roles("ADMIN")
                .build();

        var user2 = User.withUsername("jane")
                .password("12345")
//                .authorities("ROLE_MANAGER")
                .roles("MANAGER")
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
