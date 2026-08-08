/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import jakarta.servlet.http.HttpServletRequest;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/** Created by jason on 9/29/17. */
@RestController
@AssignmentHints({"csrf-get.hint1", "csrf-get.hint2", "csrf-get.hint3", "csrf-get.hint4"})
public class CSRFConfirmFlag1 implements AssignmentEndpoint {

  private final LessonSession userSessionData;

  public CSRFConfirmFlag1(LessonSession userSessionData) {
    this.userSessionData = userSessionData;
  }

  @PostMapping(
      path = "/csrf/confirm-flag-1",
      produces = {"application/json"})
  @ResponseBody
  public AttackResult completed(String confirmFlagVal, HttpServletRequest request) {
    if (!startedOnThisSite(request)) {
      return failed(this).build();
    }
    Object userSessionDataStr = userSessionData.getValue("csrf-get-success");
    if (userSessionDataStr != null && confirmFlagVal.equals(userSessionDataStr.toString())) {
      return success(this)
          .feedback("csrf-get-null-referer.success")
          .output("Correct, the flag was " + userSessionData.getValue("csrf-get-success"))
          .build();
    }

    return failed(this).build();
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
