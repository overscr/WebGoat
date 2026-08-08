/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.idor;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"idor.hints.idor_login"})
public class IDORLogin implements AssignmentEndpoint {
  private final LessonSession lessonSession;

  private final Map<String, Map<String, String>> idorUserInfo = new HashMap<>();

  // The account secret is not part of the source (and is therefore not part of the distribution
  // either): it is drawn from SecureRandom when the application starts and only its salted digest
  // is retained. Passwords are never kept in clear text and are compared in constant time.
  private final byte[] passwordSalt = new byte[16];
  private final byte[] passwordDigest;

  public IDORLogin(LessonSession lessonSession) {
    this.lessonSession = lessonSession;

    SecureRandom secureRandom = new SecureRandom();
    secureRandom.nextBytes(passwordSalt);
    byte[] secret = new byte[32];
    secureRandom.nextBytes(secret);
    this.passwordDigest = digest(Base64.getEncoder().encodeToString(secret));
  }

  public void initIDORInfo() {

    idorUserInfo.put("tom", new HashMap<String, String>());
    idorUserInfo.get("tom").put("id", "2342384");
    idorUserInfo.get("tom").put("color", "yellow");
    idorUserInfo.get("tom").put("size", "small");

    idorUserInfo.put("bill", new HashMap<String, String>());
    idorUserInfo.get("bill").put("id", "2342388");
    idorUserInfo.get("bill").put("color", "brown");
    idorUserInfo.get("bill").put("size", "large");
  }

  @PostMapping("/IDOR/login")
  @ResponseBody
  public AttackResult completed(@RequestParam String username, @RequestParam String password) {
    initIDORInfo();

    if (idorUserInfo.containsKey(username)
        && "tom".equals(username)
        && MessageDigest.isEqual(passwordDigest, digest(password))) {
      lessonSession.setValue("idor-authenticated-as", username);
      lessonSession.setValue("idor-authenticated-user-id", idorUserInfo.get(username).get("id"));
      return success(this).feedback("idor.login.success").feedbackArgs(username).build();
    }
    // the same answer for an unknown account and for a wrong password
    return failed(this).feedback("idor.login.failure").build();
  }

  private byte[] digest(String password) {
    try {
      MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
      messageDigest.update(passwordSalt);
      return messageDigest.digest(
          password == null ? new byte[0] : password.getBytes(StandardCharsets.UTF_8));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 is not available", e);
    }
  }
}
