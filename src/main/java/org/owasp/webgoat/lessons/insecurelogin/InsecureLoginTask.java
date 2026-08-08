/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.insecurelogin;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
public class InsecureLoginTask implements AssignmentEndpoint {

  @PostMapping("/InsecureLogin/task")
  @ResponseBody
  public AttackResult completed(@RequestParam String username, @RequestParam String password) {
    // A pair of credentials compiled into a controller — and shipped over the wire in the
    // clear for anyone watching the request to read — is not authentication. Sign-in belongs
    // to the application's own security layer, so nothing is granted here.
    return failed(this).build();
  }

  @PostMapping("/InsecureLogin/login")
  @ResponseStatus(HttpStatus.ACCEPTED)
  public void login() {
    // only need to exists as the JS needs to call an existing endpoint
  }
}
