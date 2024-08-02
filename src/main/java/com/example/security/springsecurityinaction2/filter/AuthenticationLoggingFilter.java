package com.example.security.springsecurityinaction2.filter;


import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.logging.Logger;

public class AuthenticationLoggingFilter /*implements Filter*/ extends OncePerRequestFilter {

    private final Logger logger = Logger.getLogger(AuthenticationLoggingFilter.class.getName());

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String requestId = request.getHeader("Request-Id");

        logger.info("Successfully authenticated request with id " +  requestId);

        filterChain.doFilter(request, response);
    }


//    @Override
//    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
//
//        var httpRequest = (HttpServletRequest) servletRequest;
//
//        var requestId = httpRequest.getHeader("Request-Id");
//
//        logger.info("Successfully authenticated request with id " + requestId);
//
//        filterChain.doFilter(servletRequest, servletResponse);
//    }

}
