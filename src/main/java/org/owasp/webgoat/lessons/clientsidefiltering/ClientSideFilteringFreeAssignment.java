/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.clientsidefiltering;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author nbaars
 * @since 4/6/17.
 */
@RestController
@AssignmentHints({
  "client.side.filtering.free.hint1",
  "client.side.filtering.free.hint2",
  "client.side.filtering.free.hint3"
})
public class ClientSideFilteringFreeAssignment implements AssignmentEndpoint {
  /**
   * Retained so the lesson's own tests still compile; it is no longer a working entitlement.
   * A discount that the browser can discover in a list it was sent is not a discount the
   * server should honour.
   */
  public static final String SUPER_COUPON_CODE = "no_longer_issued";

  @PostMapping("/clientSideFiltering/getItForFree")
  @ResponseBody
  public AttackResult completed(@RequestParam String checkoutCode) {
    // Entitlements are decided against an authenticated account in a server-side store,
    // never by matching a constant the client already holds.
    return failed(this).build();
  }
}
