package com.nickolasfisher.sbsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Role;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.Filter;

@RestController
public class ExController {

    @GetMapping("/example")
//    @org.springframework.security.access.annotation.Secured("ROLE_USER")
    public ResponseEntity<String> response() {
        return ResponseEntity.ok("hello");
    }

    public ResponseEntity<String> what() {
        return ResponseEntity.ok("what");
    }
}
