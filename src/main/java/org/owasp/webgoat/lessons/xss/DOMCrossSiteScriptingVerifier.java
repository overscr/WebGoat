/*
 * SPDX-FileCopyrightText: Copyright © 2016 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.xss;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/** Created by jason on 11/23/16. */
@RestController
@AssignmentHints(
    value = {
      "xss-dom-message-hint-1",
      "xss-dom-message-hint-2",
      "xss-dom-message-hint-3",
      "xss-dom-message-hint-4",
      "xss-dom-message-hint-5",
      "xss-dom-message-hint-6"
    })
public class DOMCrossSiteScriptingVerifier implements AssignmentEndpoint {

  private final LessonSession lessonSession;

  public DOMCrossSiteScriptingVerifier(LessonSession lessonSession) {
    this.lessonSession = lessonSession;
  }

  @PostMapping("/CrossSiteScripting/dom-follow-up")
  @ResponseBody
  public AttackResult completed(@RequestParam String successMessage) {
    Object expected = lessonSession.getValue("randValue");
    // A session that never reached the phone-home step has no expected value stored yet; treat
    // that the same as a wrong answer instead of letting a null on either side compare equal.
    boolean solved = expected != null && expected.equals(successMessage);
    return solved
        ? success(this).feedback("xss-dom-message-success").build()
        : failed(this).feedback("xss-dom-message-failure").build();
  }
}
// something like ...
// http://localhost:8080/WebGoat/start.mvc#test/testParam=foobar&_someVar=234902384lotslsfjdOf9889080GarbageHere%3Cscript%3Ewebgoat.customjs.phoneHome();%3C%2Fscript%3E
// or
// http://localhost:8080/WebGoat/start.mvc#test/testParam=foobar&_someVar=234902384lotslsfjdOf9889080GarbageHere<script>webgoat.customjs.phoneHome();<%2Fscript>
