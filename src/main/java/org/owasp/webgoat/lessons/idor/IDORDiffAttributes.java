/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.idor;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({
  "idor.hints.idorDiffAttributes1",
  "idor.hints.idorDiffAttributes2",
  "idor.hints.idorDiffAttributes3"
})
public class IDORDiffAttributes implements AssignmentEndpoint {

  @PostMapping("/IDOR/diff-attributes")
  @ResponseBody
  public AttackResult completed(@RequestParam String attributes) {
    String[] diffAttribs = attributes.trim().split(",");
    if (diffAttribs.length < 2) {
      return failed(this).feedback("idor.diff.attributes.missing").build();
    }
    // UserProfile#profileToMap no longer serializes the internal id or the role, so the JSON the
    // page renders and the full server-side record can no longer be diffed against each other to
    // find a field the UI was hiding.
    return failed(this).feedback("idor.diff.no.hidden.attributes").build();
  }
}
