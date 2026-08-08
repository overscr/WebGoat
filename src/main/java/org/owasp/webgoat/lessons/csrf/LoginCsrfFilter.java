/*
 * SPDX-FileCopyrightText: Copyright © 2025 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Rejects authentication requests which are submitted from another site. Without this check an
 * attacker can silently log a victim in on an account the attacker controls (login CSRF), after
 * which everything the victim does ends up in the attacker's account. Registration is guarded as
 * well because it authenticates the new account straight away.
 *
 * <p>Requests without an {@code Origin} or {@code Referer} header (command line clients, tests) are
 * left alone, only a request which states it comes from another site is refused. For those the
 * session is marked as not having been authenticated through WebGoat's own login form.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class LoginCsrfFilter extends OncePerRequestFilter {

  /**
   * Session attribute telling whether the credentials for this session were submitted by WebGoat's
   * own login form instead of by some other client or site.
   */
  static final String LOGIN_FROM_WEBGOAT = "csrf-login-from-webgoat";

  private static final String LOGIN_PATH = "/login";
  private static final String REGISTER_PATH = "/register.mvc";

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    if (RequestOrigin.isCrossOrigin(request)) {
      response.sendRedirect(request.getContextPath() + LOGIN_PATH + "?error");
      return;
    }
    if (LOGIN_PATH.equals(pathWithinApplication(request))) {
      // Overwrite on every attempt, an earlier verified login must not vouch for a later one.
      request.getSession().setAttribute(LOGIN_FROM_WEBGOAT, RequestOrigin.isSameOrigin(request));
    }
    filterChain.doFilter(request, response);
  }

  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) {
    if (!"POST".equalsIgnoreCase(request.getMethod())) {
      return true;
    }
    String path = pathWithinApplication(request);
    return !LOGIN_PATH.equals(path) && !REGISTER_PATH.equals(path);
  }

  private String pathWithinApplication(HttpServletRequest request) {
    String path = request.getRequestURI();
    if (path == null) {
      return "";
    }
    String contextPath = request.getContextPath();
    if (contextPath != null && !contextPath.isEmpty() && path.startsWith(contextPath)) {
      path = path.substring(contextPath.length());
    }
    int pathParameter = path.indexOf(';');
    if (pathParameter != -1) {
      path = path.substring(0, pathParameter);
    }
    return path;
  }
}
