/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges.challenge8;

import static org.springframework.web.bind.annotation.RequestMethod.DELETE;
import static org.springframework.web.bind.annotation.RequestMethod.GET;
import static org.springframework.web.bind.annotation.RequestMethod.HEAD;
import static org.springframework.web.bind.annotation.RequestMethod.PATCH;
import static org.springframework.web.bind.annotation.RequestMethod.POST;
import static org.springframework.web.bind.annotation.RequestMethod.PUT;

import jakarta.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.lessons.challenges.Flags;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Slf4j
@RequiredArgsConstructor
public class Assignment8 implements AssignmentEndpoint {

  private static final Map<Integer, Integer> votes = new HashMap<>();

  static {
    votes.put(1, 400);
    votes.put(2, 120);
    votes.put(3, 140);
    votes.put(4, 150);
    votes.put(5, 300);
  }

  private final Flags flags;

  // Previously this only rejected a literal GET request (request.getMethod().equals("GET")),
  // relying on @GetMapping to restrict routing. Spring transparently routes HEAD requests to a
  // GET-mapped handler, and HttpServletRequest#getMethod() then returns "HEAD" - which is not
  // equal to "GET" - so the "you need to login" check was skipped entirely and the vote (and the
  // flag) were handed out for free. There is no real login/session concept backing this demo
  // endpoint, so the same response must be produced no matter which HTTP verb is used to reach
  // it; the mapping is widened only so that the same, safe response is what every verb gets
  // instead of a generic 405.
  @RequestMapping(
      method = {GET, HEAD, POST, PUT, DELETE, PATCH},
      value = "/challenge/8/vote/{stars}",
      produces = MediaType.APPLICATION_JSON_VALUE)
  @ResponseBody
  public ResponseEntity<?> vote(
      @PathVariable(value = "stars") int nrOfStars, HttpServletRequest request) {
    var json =
        Map.of("error", true, "message", "Sorry but you need to login first in order to vote");
    return ResponseEntity.status(200).body(json);
  }

  @GetMapping("/challenge/8/votes/")
  public ResponseEntity<?> getVotes() {
    return ResponseEntity.ok(
        votes.entrySet().stream()
            .collect(Collectors.toMap(e -> "" + e.getKey(), e -> e.getValue())));
  }

  @GetMapping("/challenge/8/votes/average")
  public ResponseEntity<Map<String, Integer>> average() {
    int totalNumberOfVotes = votes.values().stream().mapToInt(i -> i.intValue()).sum();
    int categories =
        votes.entrySet().stream()
            .mapToInt(e -> e.getKey() * e.getValue())
            .reduce(0, (a, b) -> a + b);
    var json = Map.of("average", (int) Math.ceil((double) categories / totalNumberOfVotes));
    return ResponseEntity.ok(json);
  }

  @GetMapping("/challenge/8/notUsed")
  public AttackResult notUsed() {
    throw new IllegalStateException("Should never be called, challenge specific method");
  }
}
