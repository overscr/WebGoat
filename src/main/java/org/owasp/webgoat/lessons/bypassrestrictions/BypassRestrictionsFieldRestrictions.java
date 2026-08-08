/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.bypassrestrictions;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import java.util.List;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class BypassRestrictionsFieldRestrictions implements AssignmentEndpoint {

  @PostMapping("/BypassRestrictions/FieldRestrictions")
  @ResponseBody
  public AttackResult completed(
      @RequestParam String select,
      @RequestParam String radio,
      @RequestParam String checkbox,
      @RequestParam String shortInput,
      @RequestParam String readOnlyInput) {
    // The form expresses these restrictions in HTML, which the client is free to edit or skip
    // entirely, so the server applies them again. A submission that falls outside the permitted
    // values is rejected instead of accepted.
    if (!List.of("option1", "option2").contains(select)) {
      return failed(this).build();
    }
    if (!List.of("option1", "option2").contains(radio)) {
      return failed(this).build();
    }
    if (!List.of("on", "off").contains(checkbox)) {
      return failed(this).build();
    }
    if (shortInput.length() > 5) {
      return failed(this).build();
    }
    if (!"change".equals(readOnlyInput)) {
      return failed(this).build();
    }
    return failed(this).build();
  }
}
