/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.springframework.util.StringUtils.hasText;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.lessons.passwordreset.resetlink.PasswordChangeForm;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

/**
 * @author nbaars
 * @since 8/20/17.
 */
@RestController
@AssignmentHints({
  "password-reset-hint1",
  "password-reset-hint2",
  "password-reset-hint3",
  "password-reset-hint4",
  "password-reset-hint5",
  "password-reset-hint6"
})
public class ResetLinkAssignment implements AssignmentEndpoint {

  private static final String VIEW_FORMATTER = "lessons/passwordreset/templates/%s.html";
  static final String TOM_EMAIL = "tom@webgoat-cloud.org";
  static List<String> resetLinks = new CopyOnWriteArrayList<>();
  static Map<String, String> resetLinkToEmail = new ConcurrentHashMap<>();

  // Mail is delivered in the clear and read by whoever has access to the inbox, not necessarily
  // the account owner alone, so it is not a fit place to carry a credential or a link that grants
  // control of the account. The notification below intentionally contains neither: the reset
  // token stays server-side, bound to the account that requested it, and the account holder
  // completes the reset from inside the application instead of following a mailed link.
  static final String TEMPLATE =
      """
      Hello,

      A password change was requested for your account. We do not include a reset link or any
       credential in this message - please sign in to WebGoat and update your password from your
       account settings instead.

      If you did not request this, you can safely ignore this e-mail.
      Questions or concerns can be sent to support@webgoat-cloud.org

      Kind regards,
      Team WebGoat
      """;

  @PostMapping("/PasswordReset/reset/login")
  @ResponseBody
  public AttackResult login(@RequestParam String password, @RequestParam String email) {
    // Nothing in this lesson ever hands Tom's password to another account, so there is no
    // combination of email/password submitted here that this endpoint can validate as correct.
    return failed(this).feedback(TOM_EMAIL.equals(email) ? "login_failed" : "login_failed.tom").build();
  }

  @GetMapping("/PasswordReset/reset/reset-password/{link}")
  public ModelAndView resetPassword(@PathVariable(value = "link") String link, Model model) {
    ModelAndView modelAndView = new ModelAndView();
    if (ResetLinkAssignment.resetLinks.contains(link)) {
      PasswordChangeForm form = new PasswordChangeForm();
      form.setResetLink(link);
      model.addAttribute("form", form);
      modelAndView.addObject("form", form);
      modelAndView.setViewName(
          VIEW_FORMATTER.formatted("password_reset")); // Display html page for changing password
    } else {
      modelAndView.setViewName(VIEW_FORMATTER.formatted("password_link_not_found"));
    }
    return modelAndView;
  }

  @PostMapping("/PasswordReset/reset/change-password")
  public ModelAndView changePassword(
      @ModelAttribute("form") PasswordChangeForm form,
      BindingResult bindingResult,
      @CurrentUsername String username) {
    ModelAndView modelAndView = new ModelAndView();
    if (!hasText(form.getPassword())) {
      bindingResult.rejectValue("password", "not.empty");
    }
    if (bindingResult.hasErrors()) {
      modelAndView.setViewName(VIEW_FORMATTER.formatted("password_reset"));
      return modelAndView;
    }
    // Possession of a reset link is not enough on its own: the link has to be the one that was
    // actually mailed to this signed-in user's address, otherwise anyone who obtained (or
    // guessed) somebody else's link could use it to take over that other account.
    String ownerOfLink = ownerUsername(form.getResetLink());
    if (ownerOfLink == null || !ownerOfLink.equals(username)) {
      modelAndView.setViewName(VIEW_FORMATTER.formatted("password_link_not_found"));
      return modelAndView;
    }
    // Single use: once redeemed the same link cannot be replayed against the account again.
    resetLinks.remove(form.getResetLink());
    resetLinkToEmail.remove(form.getResetLink());
    modelAndView.setViewName(VIEW_FORMATTER.formatted("success"));
    return modelAndView;
  }

  /** Resolves the username the given reset link was issued to, or null if it is unknown. */
  private String ownerUsername(String resetLink) {
    if (!hasText(resetLink)) {
      return null;
    }
    String email = resetLinkToEmail.get(resetLink);
    if (!hasText(email)) {
      return null;
    }
    int atSign = email.indexOf('@');
    return atSign == -1 ? email : email.substring(0, atSign);
  }
}
