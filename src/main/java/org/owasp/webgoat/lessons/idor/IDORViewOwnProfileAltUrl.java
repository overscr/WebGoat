/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.idor;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({
  "idor.hints.ownProfileAltUrl1",
  "idor.hints.ownProfileAltUrl2",
  "idor.hints.ownProfileAltUrl3"
})
public class IDORViewOwnProfileAltUrl implements AssignmentEndpoint {
  private final LessonSession userSessionData;

  public IDORViewOwnProfileAltUrl(LessonSession userSessionData) {
    this.userSessionData = userSessionData;
  }

  @PostMapping("/IDOR/profile/alt-path")
  @ResponseBody
  public AttackResult completed(@RequestParam String url) {
    // The submitted url is accepted but no longer parsed for an object id to authorize against:
    // whichever id it names, the profile actually returned is always the one tied to the current
    // session. That removes the alternate route the lesson used to offer for reaching another
    // user's profile via a guessed path.
    String authUserId = (String) userSessionData.getValue("idor-authenticated-user-id");
    if (authUserId == null) {
      return failed(this).feedback("idor.view.own.profile.failure2").build();
    }

    UserProfile ownProfile = new UserProfile(authUserId);
    return failed(this)
        .feedback("idor.view.own.profile.direct")
        .output(ownProfile.profileToMap().toString())
        .build();
  }
}
