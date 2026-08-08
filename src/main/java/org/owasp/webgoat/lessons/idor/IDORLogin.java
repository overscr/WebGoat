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

  // Tom's password is no longer a fixed word ("cat") that ships with the source and therefore
  // ships with every WebGoat install. A fresh, unguessable value is minted from SecureRandom the
  // first time this bean is created, and only a salted SHA-256 digest of it is kept around -
  // never the value itself.
  private final byte[] loginSalt;
  private final byte[] loginPasswordHash;

  public IDORLogin(LessonSession lessonSession) {
    this.lessonSession = lessonSession;

    SecureRandom random = new SecureRandom();
    this.loginSalt = new byte[16];
    random.nextBytes(loginSalt);

    byte[] generatedPassword = new byte[24];
    random.nextBytes(generatedPassword);
    this.loginPasswordHash = hash(loginSalt, bytesToHex(generatedPassword));
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

    if (!"tom".equals(username) || !idorUserInfo.containsKey(username)) {
      // Same failure for an unknown account as for a wrong password, so a caller can't use the
      // response to tell the two apart and enumerate valid usernames.
      return failed(this).feedback("idor.login.failure").build();
    }

    byte[] submittedHash = hash(loginSalt, password);
    if (!MessageDigest.isEqual(loginPasswordHash, submittedHash)) {
      return failed(this).feedback("idor.login.failure").build();
    }

    lessonSession.setValue("idor-authenticated-as", username);
    lessonSession.setValue("idor-authenticated-user-id", idorUserInfo.get(username).get("id"));
    return success(this).feedback("idor.login.success").feedbackArgs(username).build();
  }

  private byte[] hash(byte[] salt, String value) {
    try {
      MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
      sha256.update(salt);
      sha256.update((value == null ? "" : value).getBytes(StandardCharsets.UTF_8));
      return sha256.digest();
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 must be available", e);
    }
  }

  private String bytesToHex(byte[] bytes) {
    StringBuilder hex = new StringBuilder(bytes.length * 2);
    for (byte b : bytes) {
      hex.append(String.format("%02x", b));
    }
    return hex.toString();
  }
}
