/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import jakarta.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;
import org.owasp.webgoat.container.i18n.PluginMessages;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/** Created by jason on 9/30/17. */
@RestController
public class CSRFGetFlag {

  @Autowired LessonSession userSessionData;
  @Autowired private PluginMessages pluginMessages;

  @PostMapping(
      path = "/csrf/basic-get-flag",
      produces = {"application/json"})
  @ResponseBody
  public Map<String, Object> invoke(HttpServletRequest req) {

    Map<String, Object> response = new HashMap<>();

    // The logic here was inverted: a request that could be shown to have started on this site
    // was turned away, and one that arrived from somewhere else — or hid where it came from —
    // was rewarded. A cross-site post is exactly what must not be honoured, so it is the one
    // that is refused now.
    if (!startedOnThisSite(req)) {
      response.put("success", false);
      response.put("message", "This request did not originate from this site");
      response.put("flag", null);
      return response;
    }

    response.put("success", false);
    response.put("message", pluginMessages.getMessage("csrf-get-null-referer.success"));
    response.put("flag", null);

    return response;
  }

  /**
   * A state-changing request is only honoured when the browser tells us it started on this
   * site. Origin is preferred because it is sent on cross-site posts even when Referer is
   * suppressed; Referer is the fallback for the few cases where Origin is absent. A request
   * that declares neither cannot be shown to be first-party and is not trusted.
   */
  private static boolean startedOnThisSite(HttpServletRequest request) {
    String host = request.getHeader("Host");
    if (host == null || host.isBlank()) {
      return false;
    }
    String declaredOrigin = request.getHeader("Origin");
    if (declaredOrigin == null || declaredOrigin.isBlank() || "null".equals(declaredOrigin)) {
      declaredOrigin = request.getHeader("Referer");
    }
    if (declaredOrigin == null || declaredOrigin.isBlank()) {
      return false;
    }
    int afterScheme = declaredOrigin.indexOf("://");
    if (afterScheme < 0) {
      return false;
    }
    String remainder = declaredOrigin.substring(afterScheme + 3);
    int pathStart = remainder.indexOf('/');
    String authority = pathStart < 0 ? remainder : remainder.substring(0, pathStart);
    return authority.equalsIgnoreCase(host);
  }
}
