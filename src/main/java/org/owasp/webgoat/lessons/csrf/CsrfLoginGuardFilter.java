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
 * Blocks the login and registration endpoints from being submitted cross-site. Without this a
 * remote page can silently sign a victim into an account the attacker controls (login CSRF), and
 * everything the victim subsequently does inside the application is then attributed to that
 * account. The same trick works against registration since a new account is logged in
 * immediately after it is created.
 *
 * <p>A request that carries neither {@code Origin} nor {@code Referer} at all (curl, most
 * non-browser clients, our own tests) is not rejected outright, but it also cannot prove it came
 * from WebGoat's own form, so the resulting session is not marked as having authenticated through
 * it.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class CsrfLoginGuardFilter extends OncePerRequestFilter {

  /**
   * Session attribute recording whether the credentials for this session were submitted through
   * WebGoat's own login form, as opposed to some other site or client.
   */
  static final String AUTHENTICATED_VIA_FORM = "csrf.login.viaWebGoatForm";

  private static final String LOGIN_ENDPOINT = "/login";
  private static final String REGISTER_ENDPOINT = "/register.mvc";

  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) {
    if (!"POST".equalsIgnoreCase(request.getMethod())) {
      return true;
    }
    String path = requestPath(request);
    return !LOGIN_ENDPOINT.equals(path) && !REGISTER_ENDPOINT.equals(path);
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws ServletException, IOException {
    if (SiteOriginGuard.declaresForeignSite(request)) {
      response.sendRedirect(request.getContextPath() + LOGIN_ENDPOINT + "?error");
      return;
    }
    if (LOGIN_ENDPOINT.equals(requestPath(request))) {
      // Overwrite on every attempt: an earlier verified login must not vouch for a later one.
      request
          .getSession()
          .setAttribute(AUTHENTICATED_VIA_FORM, SiteOriginGuard.confirmedSameSite(request));
    }
    chain.doFilter(request, response);
  }

  private String requestPath(HttpServletRequest request) {
    String uri = request.getRequestURI();
    if (uri == null) {
      return "";
    }
    String context = request.getContextPath();
    if (context != null && !context.isEmpty() && uri.startsWith(context)) {
      uri = uri.substring(context.length());
    }
    int pathParamStart = uri.indexOf(';');
    return pathParamStart == -1 ? uri : uri.substring(0, pathParamStart);
  }
}
