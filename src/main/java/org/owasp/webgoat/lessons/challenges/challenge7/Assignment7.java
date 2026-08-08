/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges.challenge7;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import jakarta.servlet.http.HttpServletRequest;
import java.net.URISyntaxException;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import lombok.extern.slf4j.Slf4j;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.lessons.challenges.Email;
import org.owasp.webgoat.lessons.challenges.Flags;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

/**
 * @author nbaars
 * @since 4/8/17.
 */
@RestController
@Slf4j
public class Assignment7 implements AssignmentEndpoint {

  // Kept only because it is still referenced from compiled test sources; the reset flow no
  // longer trusts this fixed value. See createPasswordReset()/resetPassword() below: the link
  // that is actually accepted is whichever one was really issued for a given reset request, not
  // this hardcoded constant.
  public static final String ADMIN_PASSWORD_LINK = "375afe1104f4a487a73823c50a9292a2";

  // Reset links that have actually been issued (mailed out) map to the username they were issued
  // for. resetPassword() only honours links that are found here, so a link can no longer be
  // derived/guessed offline (e.g. from leaked source) - it has to be the one that was really
  // generated and sent.
  private static final Map<String, String> issuedResetLinks = new ConcurrentHashMap<>();

  private static final String TEMPLATE =
      "Hi, you requested a password reset link, please use this <a target='_blank'"
          + " href='%s/WebGoat/challenge/7/reset-password/%s'>link</a> to reset your"
          + " password.\n"
          + " \n\n"
          + "If you did not request this password change you can ignore this message.\n"
          + "If you have any comments or questions, please do not hesitate to reach us at"
          + " support@webgoat-cloud.org\n\n"
          + "Kind regards, \n"
          + "Team WebGoat";

  private final Flags flags;
  private final RestTemplate restTemplate;
  private final String webWolfMailURL;
  private final String webGoatHost;
  private final String webGoatPort;

  public Assignment7(
      Flags flags,
      RestTemplate restTemplate,
      @Value("${webwolf.mail.url}") String webWolfMailURL,
      @Value("${webgoat.host}") String webGoatHost,
      @Value("${webgoat.port}") String webGoatPort) {
    this.flags = flags;
    this.restTemplate = restTemplate;
    this.webWolfMailURL = webWolfMailURL;
    this.webGoatHost = webGoatHost;
    this.webGoatPort = webGoatPort;
  }

  @GetMapping("/challenge/7/reset-password/{link}")
  public ResponseEntity<String> resetPassword(@PathVariable(value = "link") String link) {
    // Only a link that was genuinely issued (and mailed out) for the admin account is accepted.
    // Recomputing a link offline - even with full knowledge of this source and the old,
    // deterministic algorithm - is no longer sufficient, since links are unpredictable and are
    // checked against what was actually issued, not a fixed constant.
    String username = issuedResetLinks.remove(link);
    if ("admin".equalsIgnoreCase(username)) {
      return ResponseEntity.accepted()
          .body(
              "<h1>Success!!</h1>"
                  + "<img src='/WebGoat/images/hi-five-cat.jpg'>"
                  + "<br/><br/>Here is your flag: "
                  + flags.getFlag(7));
    }
    return ResponseEntity.status(HttpStatus.I_AM_A_TEAPOT)
        .body("That is not the reset link for admin");
  }

  @PostMapping("/challenge/7")
  @ResponseBody
  public AttackResult sendPasswordResetLink(@RequestParam String email, HttpServletRequest request)
      throws URISyntaxException {
    if (StringUtils.hasText(email)) {
      String username = email.substring(0, email.indexOf("@"));
      if (StringUtils.hasText(username)) {
        String link = new PasswordResetLink().createPasswordReset(username, "webgoat");
        issuedResetLinks.put(link, username);
        // The link that goes out by e-mail is built from configuration, never from the request
        // that asked for it. Trusting the Host header here would let anyone have the application
        // mail a reset link that points at a server they control.
        Email mail =
            Email.builder()
                .title("Your password reset link for challenge 7")
                .contents(
                    String.format(
                        TEMPLATE, "http://" + webGoatHost + ":" + webGoatPort, link))
                .sender("password-reset@webgoat-cloud.net")
                .recipient(username)
                .time(LocalDateTime.now())
                .build();
        restTemplate.postForEntity(webWolfMailURL, mail, Object.class);
      }
    }
    return success(this).feedback("email.send").feedbackArgs(email).build();
  }

  @GetMapping(value = "/challenge/7/.git")
  @ResponseBody
  public ResponseEntity<Void> git() {
    // A checked-out .git directory (or an archive of one) hands out the full commit history of
    // the application, which can include material that was since removed from the working tree.
    // Version control metadata has no business being reachable over HTTP at all.
    return ResponseEntity.notFound().build();
  }
}
