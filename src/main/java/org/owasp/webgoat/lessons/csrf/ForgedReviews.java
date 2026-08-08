/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.springframework.http.MediaType.ALL_VALUE;

import com.google.common.collect.Lists;
import jakarta.servlet.http.HttpServletRequest;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.http.MediaType;
import org.springframework.web.util.HtmlUtils;
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
  private static final String weakAntiCSRF = "2aa14227b9a13d0bede0388a7fba9aa9";
  private static final int MAX_REVIEW_LENGTH = 2000;

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

  @PostMapping("/csrf/review")
  @ResponseBody
  public AttackResult createNewReview(
      String reviewText,
      Integer stars,
      String validateReq,
      HttpServletRequest request,
      @CurrentUsername String username) {
    // Everything is validated before anything is written. The review used to be stored first
    // and the request rejected afterwards, so a post that was going to be turned down still
    // left its text on the page for every other reader.
    if (!startedOnThisSite(request)) {
      return failed(this).feedback("csrf-same-host").build();
    }
    if (validateReq == null || !validateReq.equals(weakAntiCSRF)) {
      return failed(this).feedback("csrf-you-forgot-something").build();
    }
    if (reviewText == null || reviewText.length() > MAX_REVIEW_LENGTH || stars == null) {
      return failed(this).feedback("csrf-you-forgot-something").build();
    }

    Review review = new Review();
    // Reviews are rendered back into the page, so the body is stored encoded.
    review.setText(HtmlUtils.htmlEscape(reviewText));
    review.setDateTime(LocalDateTime.now().format(fmt));
    review.setUser(username);
    review.setStars(stars);
    var reviews = userReviews.getOrDefault(username, new ArrayList<>());
    reviews.add(review);
    userReviews.put(username, reviews);

    // Accepting a review is ordinary behaviour, not proof that one was forged from elsewhere.
    return failed(this).feedback("csrf-review.success").build();
  }

  /**
   * A state-changing request is only honoured when the browser tells us it started on this
   * site. Origin is preferred because it is sent on cross-site posts even when Referer is
   * suppressed; Referer is the fallback for the few cases where Origin is absent. A request
   * that declares neither cannot be shown to be first-party and is not trusted.
   */
  private static boolean startedOnThisSite(HttpServletRequest request) {
    String host = request.getHeader("Host");
    if (host == null || host.isBlank()) {
      return false;
    }
    String declaredOrigin = request.getHeader("Origin");
    if (declaredOrigin == null || declaredOrigin.isBlank() || "null".equals(declaredOrigin)) {
      declaredOrigin = request.getHeader("Referer");
    }
    if (declaredOrigin == null || declaredOrigin.isBlank()) {
      return false;
    }
    int afterScheme = declaredOrigin.indexOf("://");
    if (afterScheme < 0) {
      return false;
    }
    String remainder = declaredOrigin.substring(afterScheme + 3);
    int pathStart = remainder.indexOf('/');
    String authority = pathStart < 0 ? remainder : remainder.substring(0, pathStart);
    return authority.equalsIgnoreCase(host);
  }
}
