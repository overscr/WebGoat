/*
 * SPDX-FileCopyrightText: Copyright © 2016 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Set;
import lombok.AllArgsConstructor;
import org.owasp.webgoat.container.users.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;

/** Security configuration for WebGoat. */
@Configuration
@AllArgsConstructor
@EnableWebSecurity
public class WebSecurityConfig {

  private final UserService userDetailsService;

  /**
   * Paths a client has to be able to reach before it holds a session, and therefore before it
   * can hold a token bound to one.
   */
  private static final Set<String> AUTHENTICATION_BOOTSTRAP_PATHS =
      Set.of("/login", "/logout", "/register.mvc", "/registration");

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    var tokenRepository = CookieCsrfTokenRepository.withHttpOnlyFalse();
    tokenRepository.setCookieCustomizer(cookie -> cookie.sameSite("Strict"));

    return http.authorizeHttpRequests(
            auth ->
                auth.requestMatchers(
                        "/favicon.ico",
                        "/css/**",
                        "/images/**",
                        "/js/**",
                        "fonts/**",
                        "/plugins/**",
                        "/registration",
                        "/register.mvc",
                        "/actuator/**")
                    .permitAll()
                    .anyRequest()
                    .authenticated())
        .formLogin(
            login ->
                login
                    .loginPage("/login")
                    .defaultSuccessUrl("/welcome.mvc", true)
                    .usernameParameter("username")
                    .passwordParameter("password")
                    .permitAll())
        .oauth2Login(
            oidc -> {
              oidc.defaultSuccessUrl("/login-oauth.mvc");
              oidc.loginPage("/login");
            })
        .logout(logout -> logout.deleteCookies("JSESSIONID").invalidateHttpSession(true))
        .csrf(
            csrf ->
                csrf.csrfTokenRepository(tokenRepository)
                    .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())
                    .ignoringRequestMatchers(sessionlessAuthenticationAttempt()))
        .headers(headers -> headers.disable())
        .exceptionHandling(
            handling ->
                handling.authenticationEntryPoint(new AjaxAuthenticationEntryPoint("/login")))
        .build();
  }

  /**
   * Signing in and registering happen before a session — and therefore before a token — exists,
   * so those two POSTs cannot be made to carry one on the very first request. Exempting them
   * outright would reopen the forged-login hole, so the exemption is narrowed to requests that
   * announce no browsing context at all: a form submitted by a page, wherever that page is
   * hosted, always carries an Origin or a Referer, and it is precisely those cross-site form
   * posts that the token is there to stop. A scripted client with neither header cannot be
   * riding somebody else's ambient cookies, because there is no page to have supplied them.
   */
  private static RequestMatcher sessionlessAuthenticationAttempt() {
    return request ->
        "POST".equalsIgnoreCase(request.getMethod())
            && request.getHeader("Origin") == null
            && request.getHeader("Referer") == null
            && AUTHENTICATION_BOOTSTRAP_PATHS.contains(pathWithinApplication(request));
  }

  private static String pathWithinApplication(HttpServletRequest request) {
    String uri = request.getRequestURI();
    String contextPath = request.getContextPath();
    return contextPath.isEmpty() || !uri.startsWith(contextPath)
        ? uri
        : uri.substring(contextPath.length());
  }

  @Autowired
  public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
    auth.userDetailsService(userDetailsService);
  }

  @Bean
  @Primary
  public UserDetailsService userDetailsServiceBean() {
    return userDetailsService;
  }

  @Bean
  public AuthenticationManager authenticationManager(
      AuthenticationConfiguration authenticationConfiguration) throws Exception {
    return authenticationConfiguration.getAuthenticationManager();
  }

  @Bean
  public NoOpPasswordEncoder passwordEncoder() {
    return (NoOpPasswordEncoder) NoOpPasswordEncoder.getInstance();
  }
}
