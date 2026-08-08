/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.insecurelogin;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
public class InsecureLoginTask implements AssignmentEndpoint {

  private static final String USERNAME = "CaptainJack";

  /*
   * The password is not hard coded in the sources, in the page or in the JavaScript and it is
   * never sent to the browser, so it cannot be picked up from the network traffic and replayed.
   */
  private static final String PASSWORD = generatePassword();

  @PostMapping("/InsecureLogin/task")
  @ResponseBody
  public AttackResult completed(@RequestParam String username, @RequestParam String password) {
    if (USERNAME.equals(username) && matches(password)) {
      return success(this).build();
    }
    return failed(this).build();
  }

  @PostMapping("/InsecureLogin/login")
  @ResponseStatus(HttpStatus.ACCEPTED)
  public void login() {
    // only need to exists as the JS needs to call an existing endpoint
  }

  private static boolean matches(String password) {
    if (password == null) {
      return false;
    }
    return MessageDigest.isEqual(
        PASSWORD.getBytes(StandardCharsets.UTF_8), password.getBytes(StandardCharsets.UTF_8));
  }

  private static String generatePassword() {
    byte[] secret = new byte[32];
    new SecureRandom().nextBytes(secret);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(secret);
  }
}
