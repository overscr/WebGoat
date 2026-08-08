/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Map;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"csrf-feedback-hint1", "csrf-feedback-hint2", "csrf-feedback-hint3"})
public class CSRFFeedback implements AssignmentEndpoint {

  private final LessonSession userSessionData;
  private final ObjectMapper objectMapper;

  public CSRFFeedback(LessonSession userSessionData, ObjectMapper objectMapper) {
    this.userSessionData = userSessionData;
    this.objectMapper = objectMapper;
  }

  @PostMapping(
      value = "/csrf/feedback/message",
      produces = {"application/json"})
  @ResponseBody
  public AttackResult completed(HttpServletRequest request, @RequestBody String feedback) {
    // Posting feedback changes server state, so it is refused unless the browser reports
    // that the request started on this site. That is the whole of the fix: a form hosted
    // elsewhere can still make the victim's browser send the request, but it can no longer
    // make this endpoint act on it.
    if (!startedOnThisSite(request)) {
      return failed(this).build();
    }
    try {
      // A copy is configured rather than the shared mapper, so tightening the rules for this
      // one request does not silently change how every other endpoint parses its input.
      objectMapper
          .copy()
          .enable(DeserializationFeature.FAIL_ON_IGNORED_PROPERTIES)
          .enable(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES)
          .enable(DeserializationFeature.FAIL_ON_NUMBERS_FOR_ENUMS)
          .enable(DeserializationFeature.FAIL_ON_READING_DUP_TREE_KEY)
          .enable(DeserializationFeature.FAIL_ON_MISSING_CREATOR_PROPERTIES)
          .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
          .readValue(feedback.getBytes(), Map.class);
    } catch (IOException e) {
      return failed(this).feedback(ExceptionUtils.getStackTrace(e)).build();
    }
    return failed(this).build();
  }

  @PostMapping(path = "/csrf/feedback", produces = "application/json")
  @ResponseBody
  public AttackResult flag(@RequestParam("confirmFlagVal") String flag) {
    if (flag.equals(userSessionData.getValue("csrf-feedback"))) {
      return success(this).build();
    } else {
      return failed(this).build();
    }
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

  private boolean requestContainsWebGoatCookie(Cookie[] cookies) {
    if (cookies != null) {
      for (Cookie c : cookies) {
        if (c.getName().equals("JSESSIONID")) {
          return true;
        }
      }
    }
    return false;
  }

  /*
   * Solution:
   * <form name="attack" enctype="text/plain" action="http://localhost:8080/WebGoat/csrf/feedback/message" METHOD="POST">
   *    <!-- Construct valid JSON data: {name: "HackHuang", email: "email@example.com", subject: "suggestions", message: "Fixed the invalid solution="} -->
   *    <input type="hidden" name='{"name": "HackHuang", "email": "email@example.com", "subject": "suggestions","message":"Fixed the invalid solution', value='"}'>
   * </form>
   * <script>document.attack.submit();</script>
   */

}
