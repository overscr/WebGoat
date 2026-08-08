/*
 * SPDX-FileCopyrightText: Copyright © 2016 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.xss.stored;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/** Created by jason on 11/23/16. */
@RestController
public class StoredCrossSiteScriptingVerifier implements AssignmentEndpoint {

  private final LessonSession lessonSession;

  public StoredCrossSiteScriptingVerifier(LessonSession lessonSession) {
    this.lessonSession = lessonSession;
  }

  @PostMapping("/CrossSiteScriptingStored/stored-xss-follow-up")
  @ResponseBody
  public AttackResult completed(@RequestParam String successMessage) {
    // Same round-trip weakness as the reflected follow-up: the callback value is one the
    // caller was given, so replaying it demonstrates nothing about stored script executing.
    return failed(this).feedback("xss-stored-callback-failure").build();
  }
}
