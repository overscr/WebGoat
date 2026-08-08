/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/** Created by jason on 1/5/17. */
@RestController
@AssignmentHints({
  "access-control.hidden-menus.hint1",
  "access-control.hidden-menus.hint2",
  "access-control.hidden-menus.hint3"
})
public class MissingFunctionACHiddenMenus implements AssignmentEndpoint {

  private final MissingAccessControlUserRepository userRepository;

  public MissingFunctionACHiddenMenus(MissingAccessControlUserRepository userRepository) {
    this.userRepository = userRepository;
  }

  @PostMapping(
      path = "/access-control/hidden-menu",
      produces = {"application/json"})
  @ResponseBody
  public AttackResult completed(
      String hiddenMenu1, String hiddenMenu2, @CurrentUsername String username) {
    // Hiding the "Users"/"Config" menu entries from the page for a non-admin is a UI nicety, not
    // an access control decision. Anyone can still POST here directly, so the endpoint itself has
    // to look the caller up and confirm the admin role before it treats the submitted answer as
    // meaningful.
    if (!requesterIsAdmin(username)) {
      return failed(this).feedback("access-control.hidden-menus.failure").output("").build();
    }

    boolean correctOrder = "Users".equals(hiddenMenu1) && "Config".equals(hiddenMenu2);
    boolean reversedOrder = "Config".equals(hiddenMenu1) && "Users".equals(hiddenMenu2);

    if (correctOrder) {
      return success(this).output("").feedback("access-control.hidden-menus.success").build();
    }
    if (reversedOrder) {
      return failed(this).output("").feedback("access-control.hidden-menus.close").build();
    }
    return failed(this).feedback("access-control.hidden-menus.failure").output("").build();
  }

  private boolean requesterIsAdmin(String username) {
    User requester = userRepository.findByUsername(username);
    return requester != null && requester.isAdmin();
  }
}
