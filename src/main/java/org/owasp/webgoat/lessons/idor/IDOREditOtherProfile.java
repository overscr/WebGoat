/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.idor;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({
  "idor.hints.otherProfile1",
  "idor.hints.otherProfile2",
  "idor.hints.otherProfile3",
  "idor.hints.otherProfile4",
  "idor.hints.otherProfile5",
  "idor.hints.otherProfile6",
  "idor.hints.otherProfile7",
  "idor.hints.otherProfile8",
  "idor.hints.otherProfile9"
})
public class IDOREditOtherProfile implements AssignmentEndpoint {

  private final LessonSession userSessionData;

  public IDOREditOtherProfile(LessonSession lessonSession) {
    this.userSessionData = lessonSession;
  }

  @PutMapping(path = "/IDOR/profile/{userId}", consumes = "application/json")
  @ResponseBody
  public AttackResult completed(
      @PathVariable("userId") String userId, @RequestBody UserProfile userSubmittedProfile) {

    String authUserId = (String) userSessionData.getValue("idor-authenticated-user-id");

    // Authorization check. The id in the path and any id in the request body are both attacker
    // controlled, so a profile is only editable when it is the authenticated user's own.
    if (authUserId == null || !authUserId.equals(userId)) {
      return failed(this).feedback("idor.edit.profile.failure4").build();
    }
    if (userSubmittedProfile.getUserId() != null
        && !authUserId.equals(userSubmittedProfile.getUserId())) {
      return failed(this).feedback("idor.edit.profile.failure4").build();
    }

    UserProfile currentUserProfile = new UserProfile(authUserId);
    // Only fields the owner is allowed to change are copied over. The role is server side state:
    // binding it from the request body would let anyone promote themselves.
    currentUserProfile.setColor(userSubmittedProfile.getColor());
    userSessionData.setValue("idor-updated-own-profile", currentUserProfile);

    return failed(this)
        .feedback("idor.edit.profile.failure3")
        .output(currentUserProfile.profileToMap().toString())
        .build();
  }
}
