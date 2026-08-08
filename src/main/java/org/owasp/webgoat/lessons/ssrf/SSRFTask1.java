/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.ssrf;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"ssrf.hint1", "ssrf.hint2"})
public class SSRFTask1 implements AssignmentEndpoint {

  @PostMapping("/SSRF/task1")
  @ResponseBody
  public AttackResult completed(@RequestParam String url) {
    return stealTheCheese(url);
  }

  // The page has exactly two local resources it is willing to name, compared with an exact,
  // anchored match rather than a pattern -- there is no server-side fetch here for a crafted
  // value to redirect, so naming any other resource, local or remote, simply fails.
  private static final String TOM_RESOURCE = "images/tom.png";
  private static final String JERRY_RESOURCE = "images/jerry.png";

  protected AttackResult stealTheCheese(String url) {
    try {
      StringBuilder html = new StringBuilder();

      if (TOM_RESOURCE.equals(url)) {
        html.append(
            "<img class=\"image\" alt=\"Tom\" src=\"images/tom.png\" width=\"25%\""
                + " height=\"25%\">");
        return failed(this).feedback("ssrf.tom").output(html.toString()).build();
      } else if (JERRY_RESOURCE.equals(url)) {
        html.append(
            "<img class=\"image\" alt=\"Jerry\" src=\"images/jerry.png\" width=\"25%\""
                + " height=\"25%\">");
        return success(this).feedback("ssrf.success").output(html.toString()).build();
      } else {
        html.append("<img class=\"image\" alt=\"Silly Cat\" src=\"images/cat.jpg\">");
        return failed(this).feedback("ssrf.failure").output(html.toString()).build();
      }
    } catch (Exception e) {
      e.printStackTrace();
      return failed(this).output(e.getMessage()).build();
    }
  }
}
