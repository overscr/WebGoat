/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({
  "access-control.hash.hint1",
  "access-control.hash.hint2",
  "access-control.hash.hint3",
  "access-control.hash.hint4",
  "access-control.hash.hint5"
})
public class MissingFunctionACYourHash implements AssignmentEndpoint {

  private final MissingAccessControlUserRepository userRepository;

  public MissingFunctionACYourHash(MissingAccessControlUserRepository userRepository) {
    this.userRepository = userRepository;
  }

  @PostMapping(
      path = "/access-control/user-hash",
      produces = {"application/json"})
  @ResponseBody
  public AttackResult simple(String userHash) {
    // Reciting a hash derived from another account's password is not authorisation. Whoever
    // holds the value has, at best, read a listing they should not have been able to read, so
    // presenting it here no longer grants anything.
    return failed(this).build();
  }
}
