package com.example.security.springsecurityinaction2.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @GetMapping("/hello")
    public String hello() {
        return "hello";
    }

    @GetMapping("/ciao")
    public String ciao() {
        return "Ciao!";
    }

    @GetMapping("/hola")
    public String hola() {
        return "Hola!";
    }

}
