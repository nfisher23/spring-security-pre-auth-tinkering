package com.nickolasfisher.sbsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.DelegatingFilterProxy;

import javax.annotation.PostConstruct;
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.List;

@Configuration
public class MyConfig {

//    @Bean
//    public FilterChainProxy filterChainProxy() {
//        FilterChainProxy filterChainProxy = new FilterChainProxy();
//        return filterChainProxy;
//    }

//    @Component
//    @Order(Ordered.HIGHEST_PRECEDENCE)
//    public class MyFilter implements Filter {
//
//        @Override
//        public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
//            SecurityContext context = SecurityContextHolder.createEmptyContext();
//            Authentication authentication =
//                    new TestingAuthenticationToken("username", "password", "ROLE_USER");
//            context.setAuthentication(authentication);
//
//            SecurityContextHolder.setContext(context);
//
//            filterChain.doFilter(servletRequest, servletResponse);
//            SecurityContextHolder.clearContext();
//        }
//    }
//
//    public class SomethingImpl extends AbstractPreAuthenticatedProcessingFilter {
//
//        @Override
//        protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
//            return null;
//        }
//
//        @Override
//        protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
//            return null;
//        }
//    }
//
//    @Bean
//    public AbstractPreAuthenticatedProcessingFilter abstractPreAuthenticatedProcessingFilter(AuthenticationManager authenticationManager) {
//        AbstractPreAuthenticatedProcessingFilter something = new SomethingImpl();
//        something.setAuthenticationManager(authenticationManager);
//        return something;
//    }

//    @Component
//    public class MyAuthManager implements AuthenticationManager {
//
//        @Override
//        public Authentication authenticate(Authentication authentication) throws AuthenticationException {
//            authentication.setAuthenticated(true);
//            return authentication;
////            return new TestingAuthenticationToken("username", "password", "ROLE_USER");
//        }
//    }

    @Component
    public class Runner implements CommandLineRunner {

        @Autowired
        @Qualifier("springSecurityFilterChain")
        private Filter springSecurityFilterChain;

        @Override
        public void run(String... args) throws Exception {
            String noop = "";
        }
    }

}
