/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;
import static org.springframework.http.MediaType.ALL_VALUE;

import com.google.common.collect.Lists;
import jakarta.servlet.http.HttpServletRequest;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"csrf-review-hint1", "csrf-review-hint2", "csrf-review-hint3"})
public class ForgedReviews implements AssignmentEndpoint {

  private static DateTimeFormatter fmt = DateTimeFormatter.ofPattern("yyyy-MM-dd, HH:mm:ss");

  private static final Map<String, List<Review>> userReviews = new HashMap<>();
  private static final List<Review> REVIEWS = new ArrayList<>();
  private static final String CSRF_TOKEN_SESSION_KEY = "csrf-review-token";

  private final LessonSession userSessionData;

  public ForgedReviews(LessonSession userSessionData) {
    this.userSessionData = userSessionData;
  }

  static {
    REVIEWS.add(
        new Review("secUriTy", LocalDateTime.now().format(fmt), "This is like swiss cheese", 0));
    REVIEWS.add(new Review("webgoat", LocalDateTime.now().format(fmt), "It works, sorta", 2));
    REVIEWS.add(new Review("guest", LocalDateTime.now().format(fmt), "Best, App, Ever", 5));
    REVIEWS.add(
        new Review(
            "guest",
            LocalDateTime.now().format(fmt),
            "This app is so insecure, I didn't even post this review, can you pull that off too?",
            1));
  }

  @GetMapping(
      path = "/csrf/review",
      produces = MediaType.APPLICATION_JSON_VALUE,
      consumes = ALL_VALUE)
  @ResponseBody
  public Collection<Review> retrieveReviews(@CurrentUsername String username) {
    Collection<Review> allReviews = Lists.newArrayList();
    Collection<Review> newReviews = userReviews.get(username);
    if (newReviews != null) {
      allReviews.addAll(newReviews);
    }

    allReviews.addAll(REVIEWS);

    return allReviews;
  }

  @GetMapping(path = "/csrf/review/token", produces = MediaType.APPLICATION_JSON_VALUE)
  @ResponseBody
  public Map<String, String> csrfToken() {
    // Handing out a token per session, rather than baking one fixed value into the page for
    // everyone, is what makes the token useful: an attacker forging a cross site request has no
    // way to read it out of the victim's session, so it cannot be replayed the way a value that
    // is the same for every user (or hardcoded in the page source) can be.
    String token = (String) userSessionData.getValue(CSRF_TOKEN_SESSION_KEY);
    if (token == null) {
      byte[] randomBytes = new byte[24];
      new SecureRandom().nextBytes(randomBytes);
      token = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
      userSessionData.setValue(CSRF_TOKEN_SESSION_KEY, token);
    }
    return Map.of("token", token);
  }

  @PostMapping("/csrf/review")
  @ResponseBody
  public AttackResult createNewReview(
      String reviewText,
      Integer stars,
      String validateReq,
      HttpServletRequest request,
      @CurrentUsername String username) {
    // A state changing request is only accepted when it demonstrably came from this application.
    if (!RequestOrigin.isSameOrigin(request)) {
      return failed(this).feedback("csrf-you-forgot-something").build();
    }
    String expectedToken = (String) userSessionData.getValue(CSRF_TOKEN_SESSION_KEY);
    if (expectedToken == null || !tokenMatches(validateReq, expectedToken)) {
      return failed(this).feedback("csrf-you-forgot-something").build();
    }

    Review review = new Review();
    review.setText(reviewText);
    review.setDateTime(LocalDateTime.now().format(fmt));
    review.setUser(username);
    review.setStars(stars);
    var reviews = userReviews.getOrDefault(username, new ArrayList<>());
    reviews.add(review);
    userReviews.put(username, reviews);

    return failed(this).feedback("csrf-same-host").build();
  }

  /** Constant time comparison so a mismatching token cannot be recovered by timing the response. */
  private static boolean tokenMatches(String submitted, String expected) {
    if (submitted == null) {
      return false;
    }
    return MessageDigest.isEqual(
        submitted.getBytes(java.nio.charset.StandardCharsets.UTF_8),
        expected.getBytes(java.nio.charset.StandardCharsets.UTF_8));
  }
}
