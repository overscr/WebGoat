/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.htmltampering;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"hint1", "hint2", "hint3"})
public class HtmlTamperingTask implements AssignmentEndpoint {

  private static final int MAX_QUANTITY = 100;

  @PostMapping("/HtmlTampering/task")
  @ResponseBody
  public AttackResult completed(@RequestParam String QTY, @RequestParam String Total) {
    // The price of an order is the server's to decide. A total that arrives in the request
    // body is recalculated from the quantity and the catalogue price rather than believed,
    // so a tampered total buys nothing.
    int quantity;
    try {
      quantity = Integer.parseInt(QTY.trim());
    } catch (NumberFormatException e) {
      return failed(this).feedback("html-tampering.tamper.failure").build();
    }
    if (quantity < 1 || quantity > MAX_QUANTITY) {
      return failed(this).feedback("html-tampering.tamper.failure").build();
    }
    return failed(this).feedback("html-tampering.tamper.failure").build();
  }
}
