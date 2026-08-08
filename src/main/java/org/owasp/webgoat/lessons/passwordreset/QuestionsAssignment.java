/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author nbaars
 * @since 8/20/17.
 */
@RestController
public class QuestionsAssignment implements AssignmentEndpoint {

  private static final Map<String, String> COLORS = new HashMap<>();

  // The answers used to be a short, common color per user, which is exactly the kind of value an
  // attacker can enumerate in a handful of guesses (or find from a social media profile). A
  // security question answer needs the same unpredictability as a password, so each account gets
  // an answer generated from a secure random source instead of a guessable word.
  static {
    COLORS.put("admin", generateAnswer());
    COLORS.put("jerry", generateAnswer());
    COLORS.put("tom", generateAnswer());
    COLORS.put("larry", generateAnswer());
    COLORS.put("webgoat", generateAnswer());
  }

  private static String generateAnswer() {
    var bytes = new byte[16];
    new SecureRandom().nextBytes(bytes);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  @PostMapping(
      path = "/PasswordReset/questions",
      consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
  @ResponseBody
  public AttackResult passwordReset(@RequestParam Map<String, Object> json) {
    String securityQuestion = (String) json.getOrDefault("securityQuestion", "");
    String username = (String) json.getOrDefault("username", "");

    if ("webgoat".equalsIgnoreCase(username.toLowerCase())) {
      return failed(this).feedback("password-questions-wrong-user").build();
    }

    String validAnswer = COLORS.get(username.toLowerCase());
    if (validAnswer == null) {
      return failed(this)
          .feedback("password-questions-unknown-user")
          .feedbackArgs(username)
          .build();
    } else if (validAnswer.equals(securityQuestion)) {
      return success(this).build();
    }
    return failed(this).build();
  }
}
