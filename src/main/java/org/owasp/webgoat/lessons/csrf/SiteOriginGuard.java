/*
 * SPDX-FileCopyrightText: Copyright © 2025 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.net.URISyntaxException;

/**
 * Compares the site a request claims to have come from against the site actually serving it.
 * Browsers attach an {@code Origin} header (and usually a {@code Referer}) to state-changing
 * cross-site submissions; matching either against the {@code Host} header is the standard way to
 * catch a forged request before it does anything.
 */
final class SiteOriginGuard {

  private SiteOriginGuard() {}

  /**
   * True when the request carries an {@code Origin} or {@code Referer} header and it names a
   * host other than the one serving the request. Requests that carry neither header are not
   * flagged by this method; use {@link #confirmedSameSite(HttpServletRequest)} for endpoints that
   * must instead demand positive proof.
   */
  static boolean declaresForeignSite(HttpServletRequest request) {
    return conflictsWithHost(request, true);
  }

  /**
   * True only when the request positively proves it was submitted from this site. A request that
   * sends no {@code Origin} or {@code Referer} at all does not pass here, because nothing vouches
   * for it.
   */
  static boolean confirmedSameSite(HttpServletRequest request) {
    return conflictsWithHost(request, false);
  }

  private static boolean conflictsWithHost(HttpServletRequest request, boolean wantMismatch) {
    String servingHost = request.getHeader("Host");
    String claimed = claimedHost(request);
    if (claimed == null || servingHost == null) {
      return false;
    }
    boolean matches = claimed.equalsIgnoreCase(servingHost);
    return wantMismatch != matches;
  }

  private static String claimedHost(HttpServletRequest request) {
    String origin = request.getHeader("Origin");
    if (origin != null && !origin.isBlank()) {
      String trimmed = origin.trim();
      // Browsers send the opaque literal "null" as an Origin for sandboxed frames, data: URLs
      // and pages that suppress their own referrer. That can never be proven to be this site, so
      // it is treated as an explicit mismatch instead of falling through to the Referer header.
      return "null".equalsIgnoreCase(trimmed) ? "" : hostAndPort(trimmed);
    }
    String referer = request.getHeader("Referer");
    if (referer != null && !referer.isBlank()) {
      return hostAndPort(referer.trim());
    }
    return null;
  }

  /** Reduces an absolute URL down to host[:port] so it can be compared with the Host header. */
  private static String hostAndPort(String url) {
    try {
      String authority = new URI(url).getRawAuthority();
      if (authority == null) {
        return null;
      }
      int credentialsSeparator = authority.indexOf('@');
      return credentialsSeparator == -1
          ? authority
          : authority.substring(credentialsSeparator + 1);
    } catch (URISyntaxException e) {
      return null;
    }
  }
}
