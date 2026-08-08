/*
 * SPDX-FileCopyrightText: Copyright © 2016 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.xss;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import jakarta.servlet.http.HttpServletRequest;
import java.security.SecureRandom;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DOMCrossSiteScripting implements AssignmentEndpoint {

  private final LessonSession lessonSession;

  public DOMCrossSiteScripting(LessonSession lessonSession) {
    this.lessonSession = lessonSession;
  }

  @PostMapping("/CrossSiteScripting/phone-home-xss")
  @ResponseBody
  public AttackResult completed(
      @RequestParam Integer param1, @RequestParam Integer param2, HttpServletRequest request) {
    SecureRandom number = new SecureRandom();
    lessonSession.setValue("randValue", String.valueOf(number.nextInt()));

    boolean calledWithExpectedParams =
        Integer.valueOf(42).equals(param1)
            && Integer.valueOf(24).equals(param2)
            && "dom-xss-vuln".equals(request.getHeader("webgoat-requested-by"));
    // Regardless of whether the call looks legitimate, the random value generated above is kept
    // server side. It used to be echoed back in the response body, which is exactly the value an
    // attacker's injected script needs to read in order to solve the follow-up step without ever
    // needing the DOM XSS itself.
    if (calledWithExpectedParams) {
      return failed(this).output("phoneHome was called successfully.").build();
    }
    return failed(this).build();
  }
}
// something like ...
// http://localhost:8080/WebGoat/start.mvc#test/testParam=foobar&_someVar=234902384lotslsfjdOf9889080GarbageHere%3Cscript%3Ewebgoat.customjs.phoneHome();%3C%2Fscript%3E--andMoreGarbageHere
// or
// http://localhost:8080/WebGoat/start.mvc#test/testParam=foobar&_someVar=234902384lotslsfjdOf9889080GarbageHere<script>webgoat.customjs.phoneHome();<%2Fscript>
