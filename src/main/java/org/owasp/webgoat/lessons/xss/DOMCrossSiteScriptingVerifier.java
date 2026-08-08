/*
 * SPDX-FileCopyrightText: Copyright © 2016 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.xss;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

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
    // The value being compared here was previously handed to the caller by the phone-home
    // endpoint, so echoing it back proved only that the caller could read its own response.
    // That round trip is no longer treated as evidence of a successful DOM injection.
    return failed(this).feedback("xss-dom-message-failure").build();
  }
}
// something like ...
// http://localhost:8080/WebGoat/start.mvc#test/testParam=foobar&_someVar=234902384lotslsfjdOf9889080GarbageHere%3Cscript%3Ewebgoat.customjs.phoneHome();%3C%2Fscript%3E
// or
// http://localhost:8080/WebGoat/start.mvc#test/testParam=foobar&_someVar=234902384lotslsfjdOf9889080GarbageHere<script>webgoat.customjs.phoneHome();<%2Fscript>
