/*
 * SPDX-FileCopyrightText: Copyright © 2025 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.net.URISyntaxException;

/**
 * Helper to determine where a state changing request originated from. Browsers send an {@code
 * Origin} header (and normally also a {@code Referer}) on cross site form posts, comparing it with
 * the {@code Host} we are serving is the standard way to recognise a forged request.
 */
final class RequestOrigin {

  private enum Origin {
    SAME,
    FOREIGN,
    UNKNOWN
  }

  private RequestOrigin() {}

  /**
   * Returns true only when the request can be proven to come from the application itself. Requests
   * without an {@code Origin} or {@code Referer} header cannot be verified and are therefore not
   * considered same origin.
   */
  static boolean isSameOrigin(HttpServletRequest request) {
    return determine(request) == Origin.SAME;
  }

  /**
   * Returns true when the request states an origin and that origin belongs to another site. Used
   * for endpoints which must keep working for clients that do not send these headers at all.
   */
  static boolean isCrossOrigin(HttpServletRequest request) {
    return determine(request) == Origin.FOREIGN;
  }

  private static Origin determine(HttpServletRequest request) {
    String host = request.getHeader("Host");
    if (host == null || host.isBlank()) {
      return Origin.UNKNOWN;
    }
    String origin = request.getHeader("Origin");
    if (origin != null && !origin.isBlank()) {
      // A browser sends the opaque origin "null" for sandboxed frames, data urls and pages which
      // suppress their referrer. That is never our own origin, so it counts as foreign.
      if ("null".equalsIgnoreCase(origin.trim())) {
        return Origin.FOREIGN;
      }
      return sameAuthority(host, origin.trim()) ? Origin.SAME : Origin.FOREIGN;
    }
    String referer = request.getHeader("Referer");
    if (referer != null && !referer.isBlank()) {
      return sameAuthority(host, referer.trim()) ? Origin.SAME : Origin.FOREIGN;
    }
    return Origin.UNKNOWN;
  }

  private static boolean sameAuthority(String host, String url) {
    return host.equalsIgnoreCase(authorityOf(url));
  }

  /** Reduces an absolute url to its host and port so it can be compared with the Host header. */
  private static String authorityOf(String url) {
    try {
      String authority = new URI(url).getRawAuthority();
      if (authority == null) {
        return null;
      }
      int credentials = authority.indexOf('@');
      return credentials == -1 ? authority : authority.substring(credentials + 1);
    } catch (URISyntaxException e) {
      return null;
    }
  }
}
