package com.nickolasfisher.sbsecurity;

import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.*;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.authentication.preauth.RequestHeaderAuthenticationFilter;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.util.Collection;
import java.util.Collections;

@Component
@EnableWebSecurity(debug = true)
@EnableGlobalMethodSecurity(securedEnabled=true)
public class ConfigAdapter extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.addFilterAfter(filter(), UsernamePasswordAuthenticationFilter.class)
                .authorizeRequests(expressionInterceptUrlRegistry -> expressionInterceptUrlRegistry.antMatchers("/**").authenticated());
    }

    @Bean("customPreAuthProcessingFilter")
    public AbstractPreAuthenticatedProcessingFilter filter() {
        AbstractPreAuthenticatedProcessingFilter abstractPreAuthenticatedProcessingFilter = new AbstractPreAuthenticatedProcessingFilter() {
            @Override
            protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
                return request.getHeader("prince");
            }

            @Override
            protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
                return request.getHeader("cred");
            }
        };
        abstractPreAuthenticatedProcessingFilter.setAuthenticationManager(authenticationManager());
        return abstractPreAuthenticatedProcessingFilter;
    }

    @Bean
    @Override
    protected AuthenticationManager authenticationManager() {
        return new ProviderManager(Collections.singletonList(preAuthenticatedAuthenticationProvider()));
    }

    @Bean("preAuthProvider")
    PreAuthenticatedAuthenticationProvider preAuthenticatedAuthenticationProvider() {
        PreAuthenticatedAuthenticationProvider preAuthenticatedAuthenticationProvider = new PreAuthenticatedAuthenticationProvider();
        preAuthenticatedAuthenticationProvider.setPreAuthenticatedUserDetailsService(new AuthenticationUserDetailsService<>() {
            @Override
            public UserDetails loadUserDetails(PreAuthenticatedAuthenticationToken token) throws UsernameNotFoundException {
                return new UserDetails() {
                    @Override
                    public Collection<? extends GrantedAuthority> getAuthorities() {
                        return Collections.singletonList(new SimpleGrantedAuthority((String)token.getCredentials()));
                    }

                    @Override
                    public String getPassword() {
                        return "what";
                    }

                    @Override
                    public String getUsername() {
                        return (String)token.getPrincipal();
                    }

                    @Override
                    public boolean isAccountNonExpired() {
                        return true;
                    }

                    @Override
                    public boolean isAccountNonLocked() {
                        return true;
                    }

                    @Override
                    public boolean isCredentialsNonExpired() {
                        return true;
                    }

                    @Override
                    public boolean isEnabled() {
                        return true;
                    }
                };
            }
        });
        return preAuthenticatedAuthenticationProvider;
    }

    //    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.authenticationProvider(new AuthenticationProvider() {
//            @Override
//            public Authentication authenticate(Authentication authentication) throws AuthenticationException {
//                Authentication auth = new UsernamePasswordAuthenticationToken("what", "yeah", Collections.emptyList());
//                auth.setAuthenticated(true);
//                return authentication;
//            }
//
//            @Override
//            public boolean supports(Class<?> authentication) {
//                return authentication.equals(UsernamePasswordAuthenticationToken.class);
//            }
//        });
//        auth.userDetailsService(new UserDetailsService() {
//            @Override
//            public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//                return null;
//            }
//        });
////        super.configure(auth);
//    }
//
//    @Override
//    public void configure(HttpSecurity http) throws Exception {
//        super.configure(http);
//        http.authorizeRequests().antMatchers("/**").authenticated();
//    }
}
