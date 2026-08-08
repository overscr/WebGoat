/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges.challenge1;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;
import static org.owasp.webgoat.lessons.challenges.SolutionConstants.PASSWORD;

import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.lessons.challenges.Flags;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class Assignment1 implements AssignmentEndpoint {

  // The PIN is only 4 digits (0000-9999). Without a limit on failed attempts, an attacker can
  // just script through the whole key space in seconds instead of reading it out of the
  // steganographic image, which is the actual point of the assignment. A handful of honest
  // mistakes is still tolerated per client before further attempts are refused.
  private static final int MAX_ATTEMPTS = 10;

  private final Flags flags;
  private final ConcurrentHashMap<String, AtomicInteger> failedAttemptsByClient =
      new ConcurrentHashMap<>();

  public Assignment1(Flags flags) {
    this.flags = flags;
  }

  @PostMapping("/challenge/1")
  @ResponseBody
  public AttackResult completed(
      @RequestParam String username, @RequestParam String password, HttpServletRequest request) {
    String clientId = clientId(request);
    if (isLockedOut(clientId)) {
      return failed(this).feedback("ip.address.unknown").build();
    }

    boolean ipAddressKnown = true;
    boolean passwordCorrect =
        "admin".equals(username)
            && PASSWORD
                .replace("1234", String.format("%04d", ImageServlet.PINCODE))
                .equals(password);
    if (passwordCorrect && ipAddressKnown) {
      failedAttemptsByClient.remove(clientId);
      return success(this).feedback("challenge.solved").feedbackArgs(flags.getFlag(1)).build();
    }
    recordFailedAttempt(clientId);
    if (passwordCorrect) {
      return failed(this).feedback("ip.address.unknown").build();
    }
    return failed(this).build();
  }

  private boolean isLockedOut(String clientId) {
    AtomicInteger attempts = failedAttemptsByClient.get(clientId);
    return attempts != null && attempts.get() >= MAX_ATTEMPTS;
  }

  private void recordFailedAttempt(String clientId) {
    failedAttemptsByClient.computeIfAbsent(clientId, id -> new AtomicInteger()).incrementAndGet();
  }

  private String clientId(HttpServletRequest request) {
    String forwardedFor = request.getHeader("X-Forwarded-For");
    if (forwardedFor != null && !forwardedFor.isBlank()) {
      return forwardedFor.split(",")[0].trim() + "-" + Instant.now().toEpochDay();
    }
    return request.getRemoteAddr() + "-" + Instant.now().toEpochDay();
  }
}
