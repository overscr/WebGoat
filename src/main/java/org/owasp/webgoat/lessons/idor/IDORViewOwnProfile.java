/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.idor;

import java.util.HashMap;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Slf4j
public class IDORViewOwnProfile {

  private final LessonSession userSessionData;

  public IDORViewOwnProfile(LessonSession userSessionData) {
    this.userSessionData = userSessionData;
  }

  @GetMapping(
      path = {"/IDOR/own", "/IDOR/profile"},
      produces = {"application/json"})
  @ResponseBody
  public Map<String, Object> invoke() {
    Map<String, Object> details = new HashMap<>();
    try {
      if (!"tom".equals(userSessionData.getValue("idor-authenticated-as"))) {
        details.put(
            "error",
            "You do not have privileges to view the profile. Authenticate as tom first please.");
        return details;
      }
      String authUserId = (String) userSessionData.getValue("idor-authenticated-user-id");
      UserProfile userProfile = new UserProfile(authUserId);
      // userId and role are server-side bookkeeping, not profile content: leaving them out of
      // this map keeps them out of the JSON the browser receives.
      details.put("name", userProfile.getName());
      details.put("color", userProfile.getColor());
      details.put("size", userProfile.getSize());
    } catch (Exception ex) {
      log.error("something went wrong: {}", ex.getMessage());
    }
    return details;
  }
}
