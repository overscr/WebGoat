/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.insecurelogin;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.security.SecureRandom;
import java.util.Base64;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
public class InsecureLoginTask implements AssignmentEndpoint {

  private static final String EXPECTED_USER = "CaptainJack";

  // The point of this lesson is that the login form posts over plain HTTP, so the credentials are
  // readable on the wire. A fixed password such as "BlackPearl" made that observation moot: the
  // value was already public knowledge from the source. Generating an unguessable one here means
  // the only way to learn it is to actually capture the traffic, which is the exploit the lesson
  // wants to teach.
  private static final String EXPECTED_PASSWORD = randomToken();

  @PostMapping("/InsecureLogin/task")
  @ResponseBody
  public AttackResult completed(@RequestParam String username, @RequestParam String password) {
    if (EXPECTED_USER.equals(username) && EXPECTED_PASSWORD.equals(password)) {
      return success(this).build();
    }
    return failed(this).build();
  }

  @PostMapping("/InsecureLogin/login")
  @ResponseStatus(HttpStatus.ACCEPTED)
  public void login() {
    // only need to exists as the JS needs to call an existing endpoint
  }

  private static String randomToken() {
    byte[] raw = new byte[24];
    new SecureRandom().nextBytes(raw);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
  }
}
